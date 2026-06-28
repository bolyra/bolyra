# Construction

## 1. Statement of claim

An AI agent holding a 64-bit cumulative permission bitmask proves to a resource server (RS) that `permissionBitmask & requiredMask == requiredMask` — i.e., every bit the RS demands is set — without the RS learning any other bit of the bitmask, without any Authorization Server (AS) roundtrip at proof time, and in a setting where the AS itself may be adversarial (lying about or withholding the agent's actual permissions). The proof is constant-size (3 G1 + 1 G2 elements for Groth16, or ~192 bytes) regardless of bitmask width, and binds to the agent's runtime model identity (model hash, operator key, credential commitment).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, and W3C VC + BBS+ can simultaneously achieve AS-blindness, adversarial-AS soundness, bitwise predicate evaluation over a committed bitmask with implication closure, constant-size proof, and runtime model binding.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `SelectiveScopeProof`

This is a specialization of the existing `AgentPolicy` circuit that makes the selective-disclosure property explicit as a standalone verifiable artifact an RS can check without the full handshake.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Poseidon hash of the model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration (Unix) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint | Actual Merkle proof depth |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Merkle sibling hashes |
| `blindingNonce` | field | Random per-presentation blinding for unlinkability |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Verifier-attested current time |
| `agentMerkleRoot` | field | On-chain agent tree root (RS reads from registry) |
| `sessionNonce` | field | Fresh per-request nonce from RS |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeSatisfied` | bit | Always 1 if proof verifies (forced by constraint) |
| `blindedNullifier` | field | `Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)` |
| `blindedScopeCommitment` | field | `Poseidon2(Poseidon2(permissionBitmask, credentialCommitment), blindingNonce)` |

Note on `blindedScopeCommitment`: the raw `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is computed as a **private intermediate signal** inside the circuit but is never exposed as a public output. Only the blinded form — randomized with the prover-chosen `blindingNonce` — appears in public outputs. This ensures that two presentations from the same agent with the same bitmask produce distinct public outputs (under distinct `blindingNonce` values), preventing the RS from correlating presentations by scope commitment equality. When delegation chaining is needed, the unblinded `scopeCommitment` is passed as a **private input** to the downstream `Delegation` circuit (which already accepts `previousScopeCommitment` and verifies it against the delegator's credential internally); it is never revealed to the RS.

### Constraint system (gadgets)

```
// G1: Range checks
permBits[64] = Num2Bits(64)(permissionBitmask)
reqBits[64]  = Num2Bits(64)(requiredScopeMask)
Num2Bits(64)(expiryTimestamp)
Num2Bits(64)(currentTimestamp)

// G2: Credential commitment
credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx,
    operatorPubkeyAy, permissionBitmask, expiryTimestamp)

// G3: EdDSA signature verification (operator signed this credential)
EdDSAPoseidonVerifier(
    enabled=1,
    Ax=operatorPubkeyAx, Ay=operatorPubkeyAy,
    S=sigS, R8x=sigR8x, R8y=sigR8y,
    M=credentialCommitment
)

// G4: Merkle membership (credential is enrolled on-chain)
computedRoot = BinaryMerkleRoot(20)(
    leaf=credentialCommitment,
    depth=merkleProofLength,
    index=merkleProofIndex,
    siblings=merkleProofSiblings
)
computedRoot === agentMerkleRoot

// G5: Selective scope satisfaction (bitwise predicate)
for i in 0..63:
    reqBits[i] * (1 - permBits[i]) === 0
// Every required bit must be present in the actual bitmask.
// The RS learns ONLY that the predicate holds, not which
// unrequired bits are set.

// G6: Cumulative bit implication closure
permBits[4] * (1 - permBits[3]) === 0
permBits[4] * (1 - permBits[2]) === 0
permBits[3] * (1 - permBits[2]) === 0

// G7: Expiry check
LessThan(64)(currentTimestamp, expiryTimestamp) === 1

// G8: Nullifier (replay prevention) — blinded
rawNullifier = Poseidon2(credentialCommitment, sessionNonce)
blindedNullifier = Poseidon2(rawNullifier, blindingNonce)

// G9: Scope commitment — private intermediate, blinded for output
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
blindedScopeCommitment = Poseidon2(scopeCommitment, blindingNonce)

// G10: Force public output
scopeSatisfied <== 1  // tautological if proof verifies
```

### Verification protocol (RS-side)

1. RS generates fresh `sessionNonce`, reads `agentMerkleRoot` from on-chain registry (or a cached signed root).
2. RS sends `(requiredScopeMask, currentTimestamp, agentMerkleRoot, sessionNonce)` to the agent.
3. Agent generates Groth16 proof π using private credential data, sampling a fresh `blindingNonce` uniformly at random from F_p.
4. Agent sends `(π, pubSignals)` to RS.
5. RS verifies: `Groth16.Verify(vkey, pubSignals, π)` — checks that `agentMerkleRoot` matches on-chain, `sessionNonce` matches its challenge, `currentTimestamp` is within tolerance, and `scopeSatisfied == 1`.
6. No AS was contacted. RS is convinced.

### Delegation chaining interop

When the agent enters a delegation chain after the selective scope proof, the unblinded `scopeCommitment` (a private witness value the prover retains) is supplied as the `previousScopeCommitment` public input to the `Delegation` circuit. The on-chain registry stores the `blindedScopeCommitment` from the `SelectiveScopeProof` and, upon receiving a delegation proof, verifies the chain link by having the delegation circuit re-derive `blindedScopeCommitment = Poseidon2(previousScopeCommitment, blindingNonce)` internally and match it against the stored value. The `blindingNonce` used in the initial proof is provided as a private input to the delegation circuit for this re-derivation. This preserves the chain-linking property without ever exposing the raw `scopeCommitment` publicly.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:

- The Authorization Server (can forge introspection responses, lie about scope)
- Network between agent and RS (can intercept, replay, modify messages)
- Up to `n - 1` colluding agents in the Merkle tree
- Observation of all prior proof transcripts to/from this RS and other RSes

The adversary does NOT control:

- The on-chain registry contract (Merkle roots are public, immutable once posted)
- The Groth16 CRS (trusted setup is assumed honest)
- The agent's EdDSA private key or secret credential fields
- The agent's choice of `blindingNonce` (sampled locally by the prover)

### Operator / AS separation — when the adversarial-AS model has teeth

The adversarial-AS claim requires that the entity operating the agent (the **operator**, who holds the EdDSA signing key and enrolls credential commitments on-chain) is architecturally distinct from the entity the RS would otherwise query for scope information (the **AS**). If the operator and AS are the same party, the adversarial-AS model collapses: compromising the AS is equivalent to compromising the operator's signing key, which is outside the adversary's capability set.

The model is non-trivial — i.e., the adversary gains a real capability by corrupting the AS — in deployments where:

1. **The operator is not the RS's trust anchor.** The operator enrolls the credential on-chain; the RS verifies against the on-chain Merkle root. No AS mediates this. In an OAuth equivalent, the RS would need an AS to vouch for the operator's credential — and that AS could lie.

2. **Multiple independent operators share a single agent tree.** Different organizations (employers, fintech platforms, healthcare systems) each sign credentials with their own EdDSA keys and enroll them into the same Bolyra agent Merkle tree. No single AS governs the full tree. An AS that covers only a subset of operators can lie about credentials from operators it does not control — Groth16 soundness still binds the proof to the actual on-chain leaf.

3. **The RS serves agents from operators it has no bilateral trust relationship with.** This is the critical case. In traditional OAuth, the RS must either (a) trust a specific AS per-operator, creating an O(operators × RSes) policy matrix, or (b) federate through a single AS that becomes a single point of compromise. Bolyra's on-chain root is the universal trust anchor — the RS trusts the registry contract, not any operator or AS.

The deployment scenario in §7 is chosen specifically to exhibit property (2) and (3): agents credentialed by independent employer organizations present to third-party financial RSes that have no prior relationship with those employers.

### Security game: Selective Scope Unforgeability

**Game SSU(λ):**

1. Challenger runs `Setup(1^λ)` → CRS, deploys registry with empty agent tree.
2. Challenger enrolls `n` agents with known credential commitments, signed by `k` independent operators (k ≥ 2). Each operator controls its own EdDSA key pair.
3. A is given the CRS, the verification key, all public signals from prior proofs, oracle access to an adversarial AS, and **full control of up to `k - 1` operator signing keys** (modeling a compromised AS that controls some but not all operators).
4. A outputs `(π*, pubSignals*)` for a `requiredScopeMask*` and a `sessionNonce*` it has not queried before.
5. A wins if `Groth16.Verify(vkey, pubSignals*, π*) = 1` AND the credential commitment embedded in the proof either:
   - (a) is not a leaf in the agent Merkle tree at root `agentMerkleRoot*`, OR
   - (b) corresponds to an agent whose actual `permissionBitmask & requiredScopeMask* ≠ requiredScopeMask*`, OR
   - (c) corresponds to an agent whose credential has expired (`expiryTimestamp ≤ currentTimestamp*`).

Note: even with `k - 1` compromised operators, A cannot forge a proof for a credential signed by the honest operator, because that requires the honest operator's EdDSA private key (protected by assumption A3). The adversarial AS can lie about what permissions the honest operator's agents hold — but the proof is bound to the on-chain credential commitment, not to the AS's assertion.

**Claim:** `Pr[A wins SSU(λ)] ≤ negl(λ)` under the assumptions in §4.

### Security game: Scope Privacy

**Game SP(λ):**

1. Challenger enrolls two agents with bitmasks `b₀` and `b₁` such that `b₀ & requiredMask == requiredMask` and `b₁ & requiredMask == requiredMask` but `b₀ ≠ b₁`. Both agents have distinct credential commitments `cc₀` and `cc₁` (since bitmask is an input to Poseidon5).
2. Challenger flips coin `c ∈ {0, 1}`, samples a fresh `blindingNonce` uniformly at random from F_p, and generates proof `π_c` for agent `c` using this blinding nonce.
3. A is given `(π_c, pubSignals_c)` where `pubSignals_c` contains `blindedNullifier_c = Poseidon2(Poseidon2(cc_c, sessionNonce), blindingNonce)` and `blindedScopeCommitment_c = Poseidon2(Poseidon2(b_c, cc_c), blindingNonce)`.
4. A is additionally given oracle access to all prior proof transcripts from either agent to any RS (each with independently sampled blinding nonces).
5. A outputs guess `c'`.
6. A wins if `c' = c`.

**Claim:** `|Pr[c' = c] - 1/2| ≤ negl(λ)`.

**Why the blinding nonce is essential:** Without blinding, `scopeCommitment = Poseidon2(b_c, cc_c)` is deterministic in the agent's identity and bitmask. An adversary observing two presentations from distinct agents with different bitmasks (but both satisfying the required mask) would see distinct, stable `scopeCommitment` values, trivially distinguishing them across sessions. The `blindingNonce` — sampled fresh per presentation — ensures that each `blindedScopeCommitment` is a pseudorandom value even for the same underlying agent, reducing the distinguishing advantage to breaking Poseidon's PRF property.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Application |
|----|-----------|-------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + algebraic group model) | Extracting valid witness from any accepting proof |
| A2 | **Collision resistance of Poseidon** over BN254 scalar field | Binding of credential commitment, scope commitment, nullifier |
| A3 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability — cannot forge operator signature |
| A4 | **Zero-knowledge property of Groth16** (simulation-based) | Unrequired permission bits are hidden from verifier |
| A5 | **Pseudorandomness of Poseidon** (PRF assumption: `Poseidon2(·, r)` for uniform `r` is indistinguishable from a random function) | Blinded outputs hide the preimage structure |

### Reduction sketch for SSU

Suppose adversary A wins SSU with non-negligible probability ε.

**Case (a) — non-member proof:** By A1 (knowledge soundness), we can extract a witness containing `credentialCommitment` and a valid Merkle proof to `agentMerkleRoot*`. If `credentialCommitment` is not a leaf, we have found a Poseidon collision in the Merkle path computation (the extracted path authenticates a non-existent leaf to a valid root). This contradicts A2.

**Case (b) — scope violation:** The extracted witness contains `permissionBitmask` and `requiredScopeMask`. Constraint G5 forces `reqBits[i] * (1 - permBits[i]) === 0` for all i. If the predicate fails on the actual bitmask, the constraint is unsatisfied — the proof should not verify. An accepting proof with an unsatisfied constraint breaks knowledge soundness (A1).

**Case (c) — expired credential:** Constraint G7 forces `currentTimestamp < expiryTimestamp` via LessThan(64). Same argument as case (b) via A1.

**Case (d) — forged operator signature (adversarial-AS with multi-operator tree):** The extracted witness contains `(operatorPubkeyAx, operatorPubkeyAy)` and a signature `(sigR8x, sigR8y, sigS)`. Constraint G3 verifies the EdDSA signature over `credentialCommitment`. If A does not possess the honest operator's private key, producing a valid signature breaks EdDSA unforgeability on Baby Jubjub, contradicting A3. A compromised AS that controls a different operator's key can only produce proofs for credentials signed by that other operator — the credential commitment (and thus the Merkle leaf) differs, and the proof binds to the specific operator key embedded in the Poseidon5 preimage.

### Reduction sketch for SP

We show that any adversary A breaking SP with advantage ε can be used to break either Groth16 zero-knowledge (A4) or Poseidon pseudorandomness (A5).

**Step 1 — Simulator replacement.** By A4, there exists a simulator S that, given only the public inputs `(requiredScopeMask, currentTimestamp, agentMerkleRoot, sessionNonce)` and public outputs `(scopeSatisfied, blindedNullifier, blindedScopeCommitment)`, produces a proof transcript indistinguishable from a real proof. Replace the real prover with S. Any adversary distinguishing the real and simulated games breaks A4, so A's advantage changes by at most `negl(λ)`.

**Step 2 — Public output indistinguishability.** In the simulated game, A's only distinguishing information is the public output tuple. We analyze each component:

- `scopeSatisfied = 1` is identical for both agents (deterministic constant).
- `blindedNullifier = Poseidon2(Poseidon2(cc_c, sessionNonce), blindingNonce)`: The inner value `rawNullifier_c = Poseidon2(cc_c, sessionNonce)` differs between agents (distinct `cc_c`), but the outer application `Poseidon2(rawNullifier_c, blindingNonce)` with a uniform fresh `blindingNonce` produces a value computationally indistinguishable from uniform by A5 (Poseidon PRF with the randomness in the second input). Since `blindingNonce` is fresh and uniform for each presentation, `blindedNullifier_0` and `blindedNullifier_1` are each pseudorandom and independently distributed.
- `blindedScopeCommitment = Poseidon2(Poseidon2(b_c, cc_c), blindingNonce)`: Same structure. The inner value `scopeCommitment_c = Poseidon2(b_c, cc_c)` differs between agents, but `Poseidon2(scopeCommitment_c, blindingNonce)` with fresh uniform `blindingNonce` is pseudorandom by A5.

**Step 3 — Conclusion.** In the simulated game, the public outputs are computationally indistinguishable regardless of `c` (each blinded output is pseudorandom and independent of the agent index). Therefore:

```
|Pr[A wins SP] - 1/2| ≤ Adv_ZK(A4) + Adv_PRF(A5) ≤ negl(λ)
```

**Contrast with the prior (broken) construction:** The prior version exposed `scopeCommitment = Poseidon2(b_c, cc_c)` as an unblinded public output. This value is deterministic in `(b_c, cc_c)` — an adversary who knows both candidate credential commitments (which are leaves in the public Merkle tree) can simply compute `Poseidon2(b_0, cc_0)` and `Poseidon2(b_1, cc_1)` for each candidate bitmask and compare against the public output, winning SP with advantage 1. Blinding with a fresh per-presentation nonce is therefore not an optimization but a correctness requirement for the SP game.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---------------------|-----------------|--------|
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` | `AgentPolicy` circuit, spec §3.2 |
| Scope commitment (private intermediate) | `Poseidon2(permissionBitmask, credentialCommitment)` | Spec §2 (Terminology) |
| Blinded scope commitment (public output) | `Poseidon2(scopeCommitment, blindingNonce)` | New in `SelectiveScopeProof`; uses same Poseidon2 primitive |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Spec §2.2 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Spec §2.2 |
| Nullifier (blinded) | `Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)` | Raw nullifier per spec §3.2; blinding is new |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | Spec §3.2, CLAUDE.md permissions model |
| Proving system | Groth16 (REQUIRED) with PLONK as OPTIONAL alternative | Spec §2.3 |
| On-chain root | Agent root history buffer (30-entry circular) | Spec §3.1 |

The `SelectiveScopeProof` circuit is a refactored `AgentPolicy` — same constraint set plus one additional Poseidon2 call for blinding the scope commitment. All gadgets reuse existing Bolyra circuit components. The only new element is the per-presentation `blindingNonce` (a prover-local random field element) and the corresponding Poseidon2 blinding applied to both the nullifier and scope commitment outputs.

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|--------|----------------------|
| `Num2Bits(64)` × 4 (bitmask, reqMask, expiry, timestamp) | 256 |
| `Poseidon5` (credential commitment) | ~300 |
| `EdDSAPoseidonVerifier` | ~6,500 |
| `BinaryMerkleRoot(20)` (20 Poseidon2 hashes + muxes) | ~3,200 |
| Scope satisfaction (64 multiplication constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 4 (raw nullifier, blinded nullifier, scope commitment, blinded scope commitment) | ~600 |
| **Total** | **~11,050** |

This fits well within `pot16.ptau` (2^16 = 65,536 constraint capacity). The addition of one Poseidon2 call (~150 constraints) for blinding the scope commitment is negligible.

**Proving time targets:**

- Groth16 (snarkjs, browser/Node): ~3–5s on commodity hardware (11K constraints is modest)
- Groth16 (rapidsnark, native): <500ms
- PLONK alternative: <2s (rapidsnark), <5s (snarkjs) — within agent budget

**Proof size:** 3 G1 + 1 G2 = 192 bytes (Groth16). Constant regardless of bitmask width — a 64-bit mask and a hypothetical 1024-bit mask produce identically sized proofs (the wider mask adds only linear constraints, not proof size).

## 7. Concrete deployment scenario

### Primary scenario: Cross-employer agent credentials at third-party financial RSes

**Stakeholders:**

- **Employers (operators):** Acme Corp, Contoso Ltd — each independently issues EdDSA-signed agent credentials for AI agents acting on behalf of their employees. Each employer holds its own Baby Jubjub key pair and enrolls credential commitments into the shared Bolyra agent Merkle tree on Base Sepolia.
- **Resource server:** Alliant Credit Union — a top-10 US credit union (900K+ members) operating a bill-pay API available to agents from any enrolled employer, without bilateral agreements per employer.
- **Absent party (the AS that doesn't exist):** There is no centralized Authorization Server governing the cross-employer agent population. In the OAuth model, Alliant would need to either (a) stand up its own AS and onboard each employer via client registration, or (b) federate through a shared AS — either way creating an AS that, if compromised, could lie about any employer's agents.

**The adversarial-AS scenario made concrete:**

Suppose Contoso's IT infrastructure is compromised. The attacker now controls Contoso's OAuth AS (or the shared federated AS, if one exists). In the RFC 7662 model:

1. The attacker modifies Contoso's AS to return `scope: "financial_unlimited sign_on_behalf"` for any Contoso agent introspection query, even for agents that hold only `READ_DATA`.
2. Alliant's bill-pay RS queries the AS, receives the fraudulent introspection response, and grants escalated access.
3. Alliant has no cryptographic recourse — the signed JWT introspection response is valid; the AS said what it said.

In the Bolyra model:

1. The attacker compromises Contoso's infrastructure but cannot forge Acme's EdDSA key. Contoso's agents are now suspect, but Acme's agents are unaffected.
2. Even for Contoso's own agents: the attacker cannot forge a `SelectiveScopeProof` claiming `FINANCIAL_UNLIMITED` (bit 4) for a Contoso agent whose on-chain credential commitment was enrolled with `permissionBitmask = 0x01` (READ_DATA only). The Groth16 proof extracts to a witness where constraint G5 forces `reqBits[4] * (1 - permBits[4]) === 0`. Since `permBits[4] = 0` in the enrolled credential, the constraint fails. The attacker would need to either (a) enroll a new credential commitment with the escalated bitmask — which requires Contoso's EdDSA key and leaves an auditable on-chain trace, or (b) break Groth16 knowledge soundness.
3. Alliant's RS verifies the proof against the on-chain Merkle root. No AS was queried. The compromised Contoso AS is irrelevant to proof verification.

**Why the operator/AS separation matters here:** Acme and Contoso are independent operators with independent EdDSA keys. Compromising one operator (or the AS that served that operator's tokens) does not grant the ability to forge proofs for the other operator's agents. In the OAuth model, a shared or federated AS is a single point of compromise for the entire agent population. The Bolyra model replaces the AS trust anchor with an on-chain Merkle root — a public, append-only data structure where each operator's enrollments are independently signed and independently verifiable.

**Permission privacy across RSes:** When an Acme agent presents to Alliant's bill-pay API (requiring `FINANCIAL_SMALL`, bit 2) and later to a separate insurance-quote RS (requiring `READ_DATA`, bit 0), each presentation uses a fresh `blindingNonce`. The two RSes observe entirely distinct `blindedNullifier` and `blindedScopeCommitment` values. Neither RS learns the agent's full permission set, and the two RSes cannot correlate the presentations to the same agent — even if they collude. No AS coordination is needed because no AS exists in the protocol path.

### Secondary scenario (retained): Single-institution deployment

**Stakeholder:** Navy Federal Credit Union (NFCU) — largest US credit union, 13M+ members.

**Scenario:** NFCU deploys an AI agent gateway for member-facing financial operations. Agents act on behalf of members (balance inquiries, bill pay, loan applications). NFCU's compliance team requires that an agent proves it holds `FINANCIAL_SMALL` (bit 2) authorization before accessing the bill-pay API, but NFCU's bill-pay RS must NOT learn whether the agent also holds `ACCESS_PII` (bit 7) or `SIGN_ON_BEHALF` (bit 5) — those permissions are relevant to other NFCU services but would create a liability if logged by the bill-pay service under GLBA §501(b) data minimization requirements.

**Honest assessment of the adversarial-AS model here:** In this single-institution deployment, NFCU is simultaneously the operator (signs credentials) and the implicit AS (would otherwise run the introspection endpoint). The adversarial-AS claim is weaker in this setting — compromising NFCU's AS is equivalent to compromising NFCU's operator key, which is outside the threat model. The construction still delivers value in this scenario through **scope privacy** (the bill-pay RS cannot learn unrequired permission bits), **constant-size proofs**, and **GLBA data minimization** — but the adversarial-AS soundness property is not the differentiator here. The primary scenario above is the one that exercises the full threat model.

## 8. Why the baseline cannot match

| Property | SelectiveScopeProof | RFC 7662 + BBS+ Baseline | Gap |
|----------|--------------------|--------------------------|----|
| **AS-blind presentation** | Agent proves directly to RS. No AS roundtrip. AS is never contacted at proof time. | AS must issue the token and define the introspection response. Even cached JWT introspection required AS at issuance. Agent cannot choose disclosure subset at runtime without AS pre-configuring it. | Architectural: ZK proof is self-contained; OAuth is AS-mediated by design. |
| **Adversarial-AS soundness (multi-operator)** | In a multi-operator tree (Acme + Contoso agents enrolled independently), compromising one operator's AS/infrastructure cannot forge proofs for another operator's agents. Proof validity depends on on-chain Merkle root and Groth16 soundness — not on any AS assertion. The RS trusts math, not any operator or AS. | A shared or federated AS is a single point of compromise. Compromising the AS lets the attacker forge introspection responses for agents across all operators. RS has no independent verification path — the signed introspection JWT proves only that the AS said what it said. | Fundamental: OAuth introspection is an assertion protocol; Bolyra is a proof protocol. The gap is sharpest when multiple independent operators share the agent population and no single AS should be trusted over all of them. |
| **Bitwise predicate with implication closure** | Constraint G5 evaluates `reqBits[i] * (1 - permBits[i]) === 0` for all 64 bits inside the proof. Constraint G6 enforces cumulative encoding (bit 4 → bits 3, 2). The predicate is evaluated over committed private data. | BBS+ supports equality/range predicates over individual claims. It does not support bitwise AND over a multi-bit field, nor implication closure across hierarchical permission tiers. Each BBS+ claim is independent. | Expressiveness: BBS+ predicates are per-claim; Bolyra predicates are over a committed bitfield with structural invariants. |
| **Constant-size proof** | 192 bytes (Groth16). Invariant to bitmask width. A 64-bit and 1024-bit permission space produce same proof size. | JWT introspection response grows with scope count. BBS+ derived proof grows as `O(|disclosed claims|)`. For 2^64 theoretical permissions, scope enumeration is infeasible. | Complexity-theoretic: ZK proof size is determined by the proving system, not the statement's input size. |
| **Runtime model identity binding** | `credentialCommitment = Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` — the proof cryptographically commits to which model, which operator key, and which permission state. | `client_id` is a static string. No binding to model hash or runtime operator key at inference time. DPoP binds to a key but not to model identity. | Semantic: OAuth has no concept of "which model is running right now." |
| **Cross-RS unlinkability (full)** | Both `blindedNullifier` and `blindedScopeCommitment` are randomized per presentation via `blindingNonce`. Two presentations of the same credential to different RSes produce entirely distinct public outputs (under Poseidon PRF, assumption A5). No AS-level correlation since AS is not contacted. | BBS+ presentations are unlinkable at the RS layer, but the AS that issued the credential can correlate issuance events. Moreover, BBS+ does not blind the credential structure itself — only selectively discloses claims. Removing AS from the loop entirely is not possible in the OAuth model. | Bolyra eliminates both RS-layer and AS-layer correlation. The prior construction leaked a stable `scopeCommitment`; this is now fixed via per-presentation blinding. |

**The core impossibility:** RFC 7662 and its extensions are *assertion protocols* — the RS believes what a trusted party (AS) tells it. Bolyra's `SelectiveScopeProof` is a *proof protocol* — the RS verifies a mathematical statement about committed data. No amount of composing assertion protocols produces proof-level guarantees in the adversarial-AS model, because the trust anchor is the AS itself. When the AS is the adversary, assertions are worthless. Groth16 knowledge soundness holds regardless of who issued the credential, because the proof extracts to a valid witness or the Merkle root doesn't match the on-chain state.

This distinction is architectural, not incremental. It is sharpest in the multi-operator setting (§7 primary scenario), where independent operators enroll credentials into a shared on-chain tree and no single AS governs the population. A compromised operator can damage only its own agents' credentials; the RS's trust in other operators' agents is cryptographically unaffected. In the OAuth model, a compromised federated AS damages trust in the entire agent population — there is no per-operator isolation at the assertion layer.
