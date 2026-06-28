# Construction

## 1. Statement of claim

Same agent accessing different Resource Server (RS) instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that controls token issuance, observes all AS-layer traffic, and colludes with any subset of RSes to correlate per-agent traffic graphs. Formally: no PPT adversary controlling the AS and up to N-1 RSes can distinguish whether two authorization presentations at distinct RSes originate from the same agent or two independent agents, with advantage better than negligible in the security parameter.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopeIsolatedPresentation`

This circuit allows an agent to present a credential to an RS without revealing its credential commitment, nullifier linkage, or any cross-scope correlatable value. The AS is removed from the per-request hot path entirely — it only participates at enrollment time.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | 64-bit | Full permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | F_p | Actual Merkle depth |
| `merkleProofIndex` | F_p | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Merkle siblings |
| `scopeBlindingSecret` | F_p | Per-agent persistent blinding secret (distinct from identity secret) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., Poseidon hash of RS domain) |
| `requiredScopeMask` | 64-bit | Minimum permission bits required by this RS |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `presentationNonce` | F_p | Fresh per-request nonce from RS (not AS) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, scopeBlindingSecret)` — scope-bound, unlinkable across scopes |
| `presentationBinding` | F_p | `Poseidon2(scopeNullifier, presentationNonce)` — replay prevention |

**Circuit constraints:**

1. **Credential commitment:** `credComm = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`
2. **EdDSA signature verification:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credComm) === 1`
3. **Merkle membership:** `BinaryMerkleRoot(20, credComm, merkleProofIndex, merkleProofSiblings, merkleProofLength) === agentMerkleRoot`
4. **Scope satisfaction:** For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`
5. **Cumulative bit encoding:** `bitmaskBits[4]*(1-bitmaskBits[3]) === 0`, `bitmaskBits[4]*(1-bitmaskBits[2]) === 0`, `bitmaskBits[3]*(1-bitmaskBits[2]) === 0`
6. **Expiry check:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`
7. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`
8. **Scope nullifier:** `scopeNullifier = Poseidon2(scopeId, scopeBlindingSecret)`
9. **Presentation binding:** `presentationBinding = Poseidon2(scopeNullifier, presentationNonce)`
10. **Blinding secret range:** `Num2Bits(251)` on `scopeBlindingSecret` — ensures it lies in [0, 2^251)

**Key design decisions:**

- The `scopeBlindingSecret` is a per-agent random value generated once at agent provisioning and stored alongside the credential. It is independent of the credential commitment and operator key.
- `scopeNullifier = Poseidon2(scopeId, scopeBlindingSecret)` is deterministic per (agent, scope) pair — enabling Sybil detection within a single RS — but unlinkable across different `scopeId` values under the Poseidon PRF assumption.
- The AS never sees the `presentationNonce` or the `scopeNullifier`. The RS generates the nonce, the agent generates the proof locally, the RS verifies against the on-chain Merkle root. The AS is not in the loop.
- No token issuance step exists. The agent proves credential validity directly to the RS via the ZK proof. The AS's role is limited to enrollment (inserting credential commitments into the Merkle tree).

### Modified protocol flow (scope-isolated presentation)

1. Agent contacts RS-A. RS-A returns `(scopeId_A, requiredScopeMask_A, presentationNonce_A, currentTimestamp)`.
2. Agent computes `ScopeIsolatedPresentation` proof using its private credential fields and `scopeBlindingSecret`.
3. Agent sends proof + public signals to RS-A. RS-A verifies:
   - `agentMerkleRoot` is in the on-chain root history buffer
   - `scopeNullifier` has not been revoked for this scope
   - `presentationBinding` has not been used (replay check)
   - PLONK/Groth16 proof verifies
4. RS-A records `scopeNullifier` for rate-limiting/Sybil detection within its scope.
5. When the same agent contacts RS-B with `scopeId_B ≠ scopeId_A`, it produces `scopeNullifier_B = Poseidon2(scopeId_B, scopeBlindingSecret) ≠ scopeNullifier_A`.

The AS is entirely absent from steps 1–5.

## 3. Threat model (adversary capabilities, game definition)

### IND-UNL-AS Game

**Adversary A** controls:
- The Authorization Server (full key material, enrollment logs, all historical interactions)
- Up to N-1 of N Resource Servers (can see all presentations at colluding RSes)
- Network-level observation of message timing between agent and all RSes

**Adversary A** does NOT control:
- The agent's `scopeBlindingSecret` (stored locally on agent device)
- The honest RS (at least one RS is non-colluding)
- The on-chain Merkle tree integrity (public, append-only)

**Game definition:**

1. **Setup:** Challenger enrolls M agents into the Merkle tree. Each agent a_j has credential fields and a `scopeBlindingSecret_j`. Adversary A receives the full enrollment log (credential commitments, not blinding secrets).

2. **Query phase:** A adaptively requests presentations. For any (agent index j, scopeId s), A receives the full public output `(agentMerkleRoot, scopeNullifier_{j,s}, presentationBinding_{j,s,nonce})`. A may query any agent at any scope polynomially many times.

3. **Challenge:** A selects two distinct agents `a_0, a_1` and a challenge scope `s*` that A has NOT queried for either agent. Challenger flips coin b ← {0,1}, returns a presentation proof for agent `a_b` at scope `s*`.

4. **A wins** if it correctly guesses b.

**IND-UNL-AS advantage:**
```
Adv^{IND-UNL-AS}_A = |Pr[A wins] - 1/2|
```

**Claim:** For all PPT adversaries A, `Adv^{IND-UNL-AS}_A ≤ negl(λ)` under the assumptions stated in §4.

### Side-channel threat model extension

**Timing adversary:** A additionally observes timestamps of all proof verification transactions on-chain. Mitigation: agents SHOULD batch presentations and submit via a mix-net or delayed relay. The construction achieves cryptographic unlinkability; timing resistance is an operational layer concern (analogous to Tor vs. onion routing — the crypto is sound, deployment adds traffic analysis resistance).

**Nonce freshness adversary:** A compromises old `presentationNonce` values. The `presentationBinding = Poseidon2(scopeNullifier, presentationNonce)` ensures that a stale nonce produces a distinct binding, but does not help A link across scopes (the `scopeNullifier` term is scope-dependent and hidden).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF (A-PRF):** Poseidon2, keyed on its second input, is a pseudorandom function. Specifically: for random key k, `Poseidon2(·, k)` is computationally indistinguishable from a random function.

2. **Knowledge soundness of PLONK/Groth16 (A-KS):** The proving system satisfies knowledge soundness — a valid proof implies the prover knows a witness satisfying all circuit constraints.

3. **Collision resistance of Poseidon (A-CR):** Finding `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` is hard.

4. **Discrete log hardness on Baby Jubjub (A-DL):** Given `(Ax, Ay) = BabyPbk(s)`, recovering `s` is hard.

### Reduction sketch (IND-UNL-AS → PRF distinguishing)

**Theorem.** If A breaks IND-UNL-AS with advantage ε, then there exists B breaking A-PRF with advantage ≥ ε/2.

**Proof sketch:**

1. B receives oracle access to O(·) which is either `Poseidon2(·, k)` for random k, or a truly random function R(·).

2. B simulates the IND-UNL-AS game for A. During setup, B enrolls M agents honestly but for agents a_0, a_1 (the challenge pair), B does not choose a `scopeBlindingSecret`. Instead, B will use O(·) to answer challenge queries.

3. During the query phase, for any query (a_j, s) where j ∉ {0, 1}, B computes honestly. For j ∈ {0, 1} and scope s ≠ s*, B computes honestly using the actual `scopeBlindingSecret_j`.

4. At challenge time, A submits (a_0, a_1, s*). B flips b, then computes the scopeNullifier for the challenge as `O(s*)`. If O = Poseidon2(·, scopeBlindingSecret_b), this is a valid simulation. If O = R, the scopeNullifier is uniformly random and independent of b.

5. If A guesses b correctly when O = Poseidon2(·, k), A's advantage is ε. When O = R, A's advantage is 0 (the response is independent of b). Therefore B distinguishes with advantage ε/2.

**Corollary on cross-scope linkage:** Even if A observes `scopeNullifier_A = Poseidon2(scopeId_A, k)` and `scopeNullifier_B = Poseidon2(scopeId_B, k)` for the same agent, linking them requires inverting the PRF to recover k — contradicting A-PRF.

**Soundness (cannot forge credentials):** By A-KS, a valid proof implies the prover knows a credential commitment that is (a) a leaf in the Merkle tree, (b) signed by an operator, and (c) satisfies the scope mask. Forging a proof for a non-enrolled or expired credential violates knowledge soundness.

**No double-spending within scope:** Within a single scopeId, `scopeNullifier = Poseidon2(scopeId, scopeBlindingSecret)` is deterministic. Two presentations at the same RS from the same agent produce the same scopeNullifier, enabling Sybil detection.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---------------------|-----------------|--------|
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | AgentPolicy circuit (spec §3.2) |
| Scope nullifier | `Poseidon2(scopeId, scopeBlindingSecret)` | New — analogous to human nullifier `Poseidon2(scope, secret)` |
| Presentation binding | `Poseidon2(scopeNullifier, presentationNonce)` | Mirrors human `nonceBinding = Poseidon2(nullifierHash, sessionNonce)` |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Existing AgentPolicy constraint |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Existing agent Merkle tree |
| Permission check | Bitwise `requiredBits[i] * (1 - permBits[i]) === 0` | Existing AgentPolicy constraint |
| Cumulative encoding | Bits 4→3→2 implication chain | Existing AgentPolicy constraint |
| Range checks | `Num2Bits(64)` on timestamps/bitmask, `Num2Bits(251)` on blinding secret | Existing pattern from HumanUniqueness |
| Proving system | PLONK (agent circuit — avoids per-circuit ceremony) | Existing AgentPolicy PLONK support |
| On-chain root check | Root history buffer (30-entry circular) | Existing registry contract |

The `scopeBlindingSecret` is the only new private value. It mirrors the human `secret` in HumanUniqueness — an agent-side analog that enables scope-bound pseudonymity.

## 6. Circuit cost estimate

**Constraint breakdown for `ScopeIsolatedPresentation`:**

| Gadget | Constraints (approx) |
|--------|---------------------|
| Poseidon5 (credential commitment) | ~1,200 |
| EdDSAPoseidonVerifier | ~14,000 |
| BinaryMerkleRoot(20) | ~8,000 |
| Num2Bits(64) × 3 (bitmask, expiry, timestamp) | ~192 |
| Num2Bits(251) (blinding secret range) | ~251 |
| Scope satisfaction (64-bit bitwise check) | ~128 |
| Cumulative bit encoding (3 constraints) | ~3 |
| LessThan(64) (expiry check) | ~130 |
| Poseidon2 (scope nullifier) | ~500 |
| Poseidon2 (presentation binding) | ~500 |
| **Total** | **~24,900** |

This is within the 2^16 (65,536) constraint budget of `pot16.ptau`.

**Proving time targets:**

| System | Target | Feasibility |
|--------|--------|-------------|
| PLONK (agent, snarkjs) | < 5s | Yes — ~25K constraints, comparable to existing AgentPolicy |
| PLONK (agent, rapidsnark) | < 1s | Yes — rapidsnark achieves ~10x speedup over snarkjs |
| Groth16 (optional) | < 3s | Yes — Groth16 is faster than PLONK for same constraint count |

**Verification cost (on-chain):** PLONK verification is ~300K gas on EVM (single pairing check + polynomial evaluation). Groth16 is ~230K gas. Both are within Base Sepolia gas limits.

## 7. Concrete deployment scenario

### Cross-credit-union member agent

**Stakeholders:**

- **Mountain West Credit Union (MWCU)** — member's home institution, acts as the enrollment authority (AS equivalent). Enrolls the member's agent credential into the Bolyra agent Merkle tree.
- **RS-A: TurboTax Online** — tax preparation service. Needs `READ_DATA` (bit 0) to pull the member's transaction history.
- **RS-B: Zillow Mortgage Pre-Approval** — real estate platform. Needs `READ_DATA` + `FINANCIAL_SMALL` (bits 0, 2) to verify income.

**Current problem (baseline):** Under OAuth2, MWCU-as-AS sees every token request. It knows the member's agent contacted TurboTax at 9:14 AM and Zillow at 9:22 AM. MWCU can infer the member is preparing taxes and shopping for a mortgage — information it could use for targeted product offers, sell to marketing partners, or be compelled to produce under subpoena. PPIDs hide the member's identity from cross-RS correlation but NOT from MWCU itself.

**Bolyra deployment:**

1. MWCU enrolls the member's agent credential commitment into the on-chain Merkle tree during account setup. MWCU learns the credential commitment (public) but NOT the `scopeBlindingSecret` (generated and stored on the member's device).

2. Agent contacts TurboTax. TurboTax provides `scopeId = Poseidon("turbotax.intuit.com")`, `requiredScopeMask = 0x01`, and a fresh `presentationNonce`. Agent generates `ScopeIsolatedPresentation` proof locally. TurboTax verifies the proof against the on-chain Merkle root. MWCU is never contacted.

3. Agent contacts Zillow. Zillow provides `scopeId = Poseidon("zillow.com/preapproval")`, `requiredScopeMask = 0x05`, and a fresh nonce. Agent generates a separate proof. The `scopeNullifier` is completely different from the TurboTax one.

4. **MWCU sees nothing.** It is not in the verification path. It cannot correlate the two presentations. Even if MWCU colludes with TurboTax, the TurboTax `scopeNullifier` is unlinkable to the Zillow `scopeNullifier` under the Poseidon PRF assumption.

5. **TurboTax + Zillow collude?** They compare scopeNullifiers. `Poseidon2("turbotax...", k) ≠ Poseidon2("zillow...", k)`. They cannot determine whether these came from the same agent. Linking requires breaking PRF security.

### Healthcare delegation variant

**Stakeholders:** Primary care physician (PCP) issues credential → specialist referral agent. The PCP (acting as issuer) must not learn which specialists the patient's agent contacts.

Same construction applies: the referral agent uses `ScopeIsolatedPresentation` with `scopeId` per specialist practice. The PCP enrolled the credential but is absent from all subsequent presentation flows. Specialist-to-specialist linkage is prevented by scope-bound nullifiers.

## 8. Why the baseline cannot match

| Property | Baseline (PPID + RFC 8707 + DPoP + BBS+) | Bolyra ScopeIsolatedPresentation |
|----------|------------------------------------------|----------------------------------|
| **AS sees token requests** | Yes — every token is AS-issued. AS logs (agent, RS, scope, timestamp) for every request. | No — AS only participates at enrollment. Presentations are agent→RS direct, verified against on-chain Merkle root. |
| **AS can correlate cross-RS activity** | Yes — AS holds the PPID mapping table and observes all issuance events. Trivial traffic graph reconstruction. | No — AS never sees presentation events. Even with full enrollment logs, AS cannot compute scopeNullifiers without the agent's `scopeBlindingSecret`. |
| **Colluding AS+RS can deanonymize** | Yes — AS tells RS "this PPID maps to agent X." Game over. | No — AS does not know which scopeNullifier maps to which agent. The mapping `scopeNullifier = Poseidon2(scopeId, scopeBlindingSecret)` is one-way without `scopeBlindingSecret`. |
| **Cross-RS nullifier linkage** | N/A — no nullifier scheme. BBS+ multi-show unlinkability applies only within the BBS+ layer, not across OAuth token issuance events. | Unlinkable by construction: different `scopeId` → different `scopeNullifier` under PRF. Formally proven in §4. |
| **Formal security definition** | None. No RFC defines an IND-UNL-AS game or equivalent. | IND-UNL-AS game defined in §3 with reduction to Poseidon PRF assumption in §4. |
| **Timing side channel at AS** | Fully exposed — AS timestamps every token issuance. | AS is not in the loop. On-chain verification timestamps are public but attributable only to scopeNullifiers, not agent identities. |
| **Delegation chain privacy from issuer** | RFC 8693 requires AS roundtrip at every hop — full chain visible to AS. | Delegation circuit (existing Bolyra primitive) chains scope commitments without AS involvement. Combined with ScopeIsolatedPresentation, the delegatee's presentations at RSes are also AS-invisible. |

**The structural impossibility:** The OAuth/OIDC model is fundamentally AS-centric. Every authorization artifact flows through the AS. Removing the AS from the issuance path is not a configuration option — it contradicts the architecture. BBS+ helps at the RS-to-RS correlation layer but cannot address AS-level visibility because the AS is upstream of credential issuance.

Bolyra's construction eliminates the AS from the per-request path entirely. The agent proves credential validity directly to the RS using a ZK proof against a public Merkle root. The AS's role is reduced to a one-time enrollment authority — structurally equivalent to a certificate authority that never sees TLS session traffic. This architectural difference is not achievable by layering additional RFCs onto the OAuth stack; it requires a fundamentally different verification model.
