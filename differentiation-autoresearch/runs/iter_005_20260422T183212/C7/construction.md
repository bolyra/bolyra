# Construction

## 1. Statement of claim

Bolyra cryptographically binds a specific tool call to a named model instance and operator — e.g. proves "this call was made by Claude Sonnet 4.6 operated by ACME Corp under permission bitmask X" — without revealing the underlying API key, session token, or runtime secret to the verifier. No vanilla OAuth/MCP auth can bind runtime model identity to the message, because OAuth client_id identifies only the registered application, not which model/operator actually made the call.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: ModelInstanceBinding (PLONK, universal setup)

**Private inputs:**

- `modelHash`: Hash of model weights/identifier (field element)
- `operatorPubkeyAx`, `operatorPubkeyAy`: Operator BJJ public key
- `permissionBitmask`: 64-bit permission bitfield
- `expiryTimestamp`: Credential expiration (Unix timestamp)
- `operatorSigR8x`, `operatorSigR8y`, `operatorSigS`: Operator EdDSA signature over credentialCommitment
- `providerPubkeyAx`, `providerPubkeyAy`: Model provider BJJ public key (e.g. Anthropic's attestation key)
- `providerSigR8x`, `providerSigR8y`, `providerSigS`: Provider EdDSA signature over `deploymentAuthorization`
- `messagePlaintext`: The tool-call payload being bound
- `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]`: Merkle inclusion proof

**Public inputs:**

- `requiredScopeMask`: Policy requiring specific permission bits
- `currentTimestamp`: Current time (from verifier)
- `sessionNonce`: Session binding value
- `providerRegistryRoot`: Merkle root of enrolled provider public keys (on-chain)
- `providerMerkleProofLength`, `providerMerkleProofIndex`, `providerMerkleProofSiblings[8]`: Provider key enrollment proof (depth 8 supports up to 256 providers)

**Public outputs:**

- `agentMerkleRoot`: Computed credential Merkle root
- `nullifierHash`: Poseidon2(credentialCommitment, sessionNonce)
- `scopeCommitment`: Poseidon2(permissionBitmask, credentialCommitment)
- `messageHash`: Poseidon hash of messagePlaintext
- `modelOperatorFingerprint`: Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask) — public binding tuple

**Constraints enforced (in order):**

1. **Range checks**: Num2Bits(64) on permissionBitmask, expiryTimestamp, currentTimestamp.

2. **Provider attestation of (model, operator) binding** (operator-specific root-of-trust gadget):
   - `providerKeyCommitment = Poseidon2(providerPubkeyAx, providerPubkeyAy)`
   - `BinaryMerkleRoot(8)` with `providerKeyCommitment` as leaf MUST produce `providerRegistryRoot` — proving the provider key is enrolled on-chain.
   - `deploymentAuthorization = Poseidon3(modelHash, operatorPubkeyAx, operatorPubkeyAy)` — the deployment authorization token binding model identity to a specific operator key.
   - `EdDSAPoseidonVerifier(providerPubkeyAx, providerPubkeyAy, providerSigR8x, providerSigR8y, providerSigS, deploymentAuthorization)` — proving the model provider signed this specific (model, operator) pair.

3. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.

4. **Operator EdDSA signature**: `EdDSAPoseidonVerifier` over `credentialCommitment` using operator's public key.

5. **Merkle membership**: `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf MUST produce `agentMerkleRoot`.

6. **Scope satisfaction**: For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.

7. **Cumulative bit encoding**: `bitmaskBits[4] * (1 - bitmaskBits[3]) === 0`; `bitmaskBits[4] * (1 - bitmaskBits[2]) === 0`; `bitmaskBits[3] * (1 - bitmaskBits[2]) === 0`.

8. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.

9. **Message binding**: `messageHash = Poseidon(messagePlaintext)`.

10. **Nullifier**: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`.

11. **Scope commitment**: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`.

12. **Model-operator fingerprint**: `modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask)`.

### Enrollment protocol (off-chain → on-chain)

**Provider key registry (one-time setup per model provider):**

- Anthropic (or any model provider) generates a BJJ keypair: `(providerSecret, providerPk)`.
- The provider's public key commitment `Poseidon2(providerPkAx, providerPkAy)` is inserted into a depth-8 Lean Incremental Merkle Tree on the registry contract.
- The registry stores the provider key root in `providerRegistryRoot` (separate from agent/human trees).
- Key ceremony: provider generates key in an HSM; public key is published in a transparency log alongside the on-chain insertion transaction hash. Revocation = new root excluding the compromised key.

**Model attestation (per model × operator — operator-bound):**

- When an operator signs a deployment agreement for a specific model (e.g. ACME Corp licenses Claude Sonnet 4.6), the provider computes `deploymentAuthorization = Poseidon3(modelHash, operatorPubkeyAx, operatorPubkeyAy)` and signs it: `providerSig = EdDSA.Sign(providerSecret, deploymentAuthorization)`.
- The `(modelHash, operatorPk, providerSig, providerPk)` tuple is delivered to the authorized operator via a private channel (API dashboard, authenticated endpoint). Unlike the prior construction, **provider attestation tuples are NOT published to a public registry** — they are issued per-operator and need not be disclosed to any third party.
- An operator receiving an attestation for model M can only use it with their own key. The provider signature is bound to `(modelHash, operatorPkAx, operatorPkAy)`, so it is useless to any other operator.

**Credential enrollment (per operator × model):**

- Operator generates their own BJJ keypair.
- Operator constructs `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiry)` using a provider-attested `modelHash`.
- Operator signs `credentialCommitment` with their BJJ key.
- Operator submits `credentialCommitment` for insertion into the agent Merkle tree.
- **Tree insertion contract requires no additional authorization check** — the authorization is enforced entirely inside the circuit at proving time (constraint 2). Even if an unauthorized operator inserts a credential with an arbitrary `modelHash`, they cannot produce a valid proof without a provider signature over `Poseidon3(modelHash, theirPkAx, theirPkAy)`. The Merkle tree is append-only and permissionless; the circuit is the gatekeeper.
- At proving time, operator supplies both signatures (provider over deploymentAuthorization, operator over credentialCommitment) as private inputs.

### Public signal layout (PLONK, 9 signals)

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | agentMerkleRoot | Credential tree root |
| 1 | nullifierHash | Session-specific nullifier |
| 2 | scopeCommitment | Identity-bound scope hash |
| 3 | messageHash | Hash of bound tool-call payload |
| 4 | modelOperatorFingerprint | Public binding tuple |
| 5 | requiredScopeMask | Required permission bits (public input) |
| 6 | currentTimestamp | Verifier-supplied time (public input) |
| 7 | sessionNonce | Session nonce (public input) |
| 8 | providerRegistryRoot | On-chain provider key root (public input) |

## 3. Threat model (adversary capabilities, game definition)

### Scope of binding: authorization, not runtime execution

**This construction proves authorization binding, not runtime execution binding.** The `modelHash` committed in the credential and attested by the provider certifies that the provider authorized this operator to use a model identified by `modelHash`. The proof establishes: "the model provider signed a statement that operator O is authorized to make calls under model identity M, and operator O signed a credential embedding M, and this tool call is bound to that credential."

The construction does **not** prove that the physical process generating the tool-call output actually loaded the weights corresponding to `modelHash` at inference time. Proving runtime execution — that specific model weights were loaded in memory when the output was produced — requires a hardware root of trust (TEE attestation, TPM-sealed key release conditioned on binary measurement) that is outside the scope of Bolyra's cryptographic primitives. No purely cryptographic construction over (Poseidon, EdDSA, PLONK, Merkle trees) can bridge the gap between a provider's signing key and the contents of GPU memory at inference time without a hardware trust anchor.

**What authorization binding does guarantee:** An operator cannot claim a tool call was made by model M unless the provider explicitly authorized that operator for model M. The adversary model below formalizes this. For enterprises and regulators whose concern is "was this operator licensed to use this model?" — which covers billing disputes, contractual compliance, and tiered-access enforcement — authorization binding is the operative security property. For regulatory regimes that require provable chain from deployed weights to inference output (e.g., certain readings of the EU AI Act Article 16 obligations), authorization binding is necessary but not sufficient; the residual gap must be closed by a complementary TEE attestation layer outside this construction.

### Game: MODEL-BIND-FORGE (v2 — public attestation oracle)

**Adversary capabilities:**

- Controls one or more operator BJJ keypairs with legitimately enrolled credentials for model M_adv (e.g. Opus).
- **Has access to all public provider attestation tuples for all models and all other operators.** Specifically, the adversary observes `(modelHash_target, operatorPk_victim, providerSig_victim)` tuples issued to other operators for the target model. This models the worst case where attestation tuples leak or are published.
- Observes arbitrary valid proofs for other models (e.g. Sonnet proofs from other operators).
- Has oracle access to the PLONK prover for their own enrolled credentials.
- Does NOT control the model provider's BJJ signing key (HSM-held).
- Does NOT control the on-chain provider registry (governance-multisig or DAO-controlled).
- **May run arbitrary software at inference time** — the adversary is not constrained to actually run the model corresponding to `modelHash`. The game captures authorization forgery, not runtime fidelity.

**Game definition:**

1. Challenger enrolls provider key `providerPk` in the provider registry. Challenger issues operator-bound provider attestations `(modelHash_target, operatorPk_i, providerSig_i)` for a target model M_target to various operators i. Adversary receives all such tuples.
2. Adversary receives their own legitimately enrolled credentials for model M_adv ≠ M_target, including their operator-bound attestation `(modelHash_adv, adversaryPk, providerSig_adv)`. **Crucially, the adversary does NOT receive a provider attestation binding `modelHash_target` to `adversaryPk`** — because the provider never authorized the adversary for M_target.
3. Adversary wins if they produce a valid proof π where `modelOperatorFingerprint` contains `modelHash_target` AND the `operatorPubkeyAx` in the proof corresponds to the adversary's key (i.e., the adversary claims to be authorized for M_target under their own identity).

**Winning condition:** Adversary produces (π, publicSignals) such that:
- PLONK.Verify(vk, publicSignals, π) = 1
- agentMerkleRoot ∈ rootHistoryBuffer
- providerRegistryRoot matches on-chain state
- The `modelHash` committed inside `credentialCommitment` equals `modelHash_target`
- The `operatorPubkeyAx` committed inside `credentialCommitment` equals `adversaryPkAx`

**Why the public attestation oracle does not help the adversary:**

The adversary observes `providerSig_victim` which verifies as `EdDSA.Verify(providerPk, Poseidon3(modelHash_target, victimPkAx, victimPkAy), providerSig_victim) = 1`. To produce a valid proof under their own key, the adversary needs a signature that verifies as `EdDSA.Verify(providerPk, Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy), ?) = 1`. Since `adversaryPk ≠ victimPk`, the deployment authorization hashes differ: `Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy) ≠ Poseidon3(modelHash_target, victimPkAx, victimPkAy)` (by collision resistance of Poseidon3, assumption A1). The victim's signature is over a different message and cannot be reused. The adversary must forge an EdDSA signature on a new message — breaking A2.

**Alternative attack — operator key substitution:** The adversary attempts to use `victimPk` inside the proof (presenting the victim's attestation tuple) while producing the proof themselves. This fails because constraint 4 requires an operator EdDSA signature over `credentialCommitment` (which includes `operatorPubkeyAx, operatorPubkeyAy`). The adversary does not hold `victimSecret` and cannot sign `credentialCommitment` containing `victimPk`. Either:
- The adversary uses their own key in `credentialCommitment` → the deployment authorization hash mismatches the victim's provider signature → constraint 2 fails.
- The adversary uses the victim's key in `credentialCommitment` → cannot produce a valid operator signature (constraint 4) → EdDSA forgery required → breaks A2.

### Out-of-scope attack: runtime model substitution

An adversary who holds a legitimate provider attestation for model M_target — i.e., who is genuinely authorized — could run different software (or a different model) at inference time while producing valid proofs claiming M_target. This is **not a failure of the construction**; it is outside the threat model. The construction guarantees that the provider authorized the operator for the claimed model. Whether the operator honors that authorization at runtime is an operational compliance matter equivalent to a restaurant with a health certificate serving uninspected food — the certificate is valid, the violation is behavioral. Detecting runtime substitution requires hardware attestation (TEE measurement of loaded weights bound to the proving key) and is a complementary layer, not a replacement for authorization binding.

### Root-of-trust threat model: PROVIDER-FORGE (unchanged)

1. Adversary controls operator keys but not the provider BJJ key.
2. Adversary attempts to enroll a credential with `modelHash_target` without possessing a valid `providerSig` over `deploymentAuthorization = Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy)` from an enrolled provider key.
3. Adversary wins if they produce a valid proof that passes constraint 2 (provider attestation verification + provider key Merkle membership).

**Why self-attestation is eliminated:** Constraint 2 requires the provider signature to verify inside the circuit over `Poseidon3(modelHash, operatorPubkeyAx, operatorPubkeyAy)` — not just `modelHash` alone — against a provider key that is itself Merkle-included in `providerRegistryRoot`. The operator cannot:
- Forge a provider signature (EdDSA unforgeability under DL on Baby Jubjub).
- Insert their own key into the provider registry (on-chain governance controls insertion).
- Reuse another operator's provider signature (the signed message includes the operator's public key, which differs per operator — reuse requires a Poseidon3 collision, breaking A1).
- Substitute a different modelHash while reusing their own valid provider signature (EdDSA binds the signature to the exact message, which includes modelHash).

### Why permissionless tree insertion is safe

The agent Merkle tree accepts any `credentialCommitment` without checking provider authorization at insertion time. This is by design. The tree is a data structure, not an access control boundary. Authorization is enforced at proof time: a credential in the tree is useless without a matching provider signature that verifies inside the circuit (constraint 2). This design avoids the need for on-chain authorization checks during enrollment (which would require revealing the provider signature on-chain, partially deanonymizing the operator-provider relationship). The circuit is the sole gatekeeper.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| Label | Assumption |
|-------|------------|
| A1 | Collision resistance of Poseidon over BN254 scalar field (covers Poseidon2, Poseidon3, Poseidon5) |
| A2 | Discrete logarithm hardness on Baby Jubjub (EdDSA unforgeability) |
| A3 | Knowledge soundness of PLONK in the algebraic group model + ROM |

### Scope of security claim

The reduction below proves that no PPT adversary can forge an **authorization binding** — i.e., produce a valid proof claiming provider-authorized model identity M_target for an operator who was never authorized for M_target. The reduction does not and cannot cover runtime execution fidelity, which is outside the cryptographic model.

### Reduction sketch for MODEL-BIND-FORGE (v2)

**Theorem:** Any PPT adversary winning MODEL-BIND-FORGE v2 — even given all public attestation tuples for all operators — with non-negligible probability breaks A1, A2, or A3.

**Proof sketch:**

Given adversary A that wins MODEL-BIND-FORGE, extract witness via A3 (PLONK knowledge soundness). The extracted witness contains `(modelHash, operatorPkAx, operatorPkAy, permissionBitmask, expiry, providerPk, providerSig, operatorSig, merkleProof, providerMerkleProof)`.

**Case 1 (fingerprint collision):** Extracted `modelHash ≠ modelHash_target` but `modelOperatorFingerprint` matches a fingerprint containing `modelHash_target`. Then `Poseidon3(modelHash, ...) = Poseidon3(modelHash_target, ...)` with `modelHash ≠ modelHash_target` — Poseidon3 collision, breaks A1.

**Case 2 (valid modelHash, own key):** Extracted `modelHash = modelHash_target` and `operatorPkAx = adversaryPkAx`. The provider signature verifies over `deploymentAuthorization = Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy)` under an enrolled provider key. The adversary was never issued a provider signature for this message. Two sub-cases:

- **2a (signature forgery):** `providerPk` is enrolled and `providerSig` is valid on `Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy)`. No such signature was ever issued by the challenger. This is an existential EdDSA forgery — breaks A2.

- **2b (provider key not enrolled):** `providerPk` is not in the provider registry but the Merkle proof verifies against `providerRegistryRoot`. Then `Poseidon2(providerPkAx, providerPkAy)` collides with an enrolled leaf — breaks A1.

**Case 3 (valid modelHash, victim's key):** Extracted `modelHash = modelHash_target` and `operatorPkAx = victimPkAx` (adversary uses victim's key). The extracted `operatorSig` verifies over `credentialCommitment` which includes `victimPk`. Since the adversary does not hold `victimSecret`, this is an EdDSA forgery on the operator signature — breaks A2.

**Case 4 (credential commitment collision):** Extracted `credentialCommitment` was enrolled with different fields `(modelHash', opPk', ...)` but equals `Poseidon5(modelHash_target, adversaryPk, ...)`. Then `Poseidon5(modelHash', opPk', ...) = Poseidon5(modelHash_target, adversaryPk, ...)` with differing inputs — Poseidon5 collision, breaks A1.

**Case 5 (cross-operator attestation reuse):** Adversary attempts to reuse `providerSig_victim` (observed from the public attestation oracle) with their own key. The signature verifies over `Poseidon3(modelHash_target, victimPkAx, victimPkAy)`, but constraint 2 requires verification over `Poseidon3(modelHash_target, adversaryPkAx, adversaryPkAy)`. Since `adversaryPk ≠ victimPk`, these are distinct Poseidon3 inputs. For the signature to verify over the adversary's authorization hash, either the adversary forges an EdDSA signature (breaks A2) or finds a Poseidon3 collision mapping the victim's authorization hash to the adversary's (breaks A1).

### Reduction sketch for PROVIDER-FORGE

Same structure as Cases 2a/2b above, with the additional note that the adversary cannot repurpose any observed attestation tuple because every provider signature is bound to a specific `(modelHash, operatorPk)` pair.

### Key rotation survival

Operator API key rotation does not affect the construction because:
- The BJJ keypair used for credential signing is independent of any API bearer token or session key.
- Historical proofs reference a `credentialCommitment` that was enrolled under a specific BJJ public key. The Merkle root at verification time includes this commitment. Rotating the API key does not alter the Merkle tree.
- If the operator rotates their BJJ key, they enroll a new credential with the new key and obtain a new provider attestation binding the new key to the model. Old proofs remain valid against old Merkle roots stored in the 30-entry root history buffer. For long-term archival, the verifier stores the `agentMerkleRoot` from the proof at verification time.

### Provider key rotation

- Provider rotates by enrolling a new BJJ key in the provider registry and revoking the old one (new root excludes old key commitment).
- Historical proofs that used the old provider key remain valid: at verification time, the `providerRegistryRoot` public input matched the on-chain root that included the old key. Archival verifiers store the `providerRegistryRoot` alongside the proof.
- New credentials must use the new provider key's attestation.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Credential commitment | Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry) | Section 4, AgentPolicy circuit |
| Provider key commitment | Poseidon2(providerPkAx, providerPkAy) | Analogous to identity commitment (Section 4, HumanUniqueness) |
| Deployment authorization | Poseidon3(modelHash, operatorPkAx, operatorPkAy) | Operator-bound attestation token |
| Provider attestation | EdDSA on Baby Jubjub over deploymentAuthorization | Same primitive as operator signature, binding (model, operator) |
| Operator signature | EdDSAPoseidonVerifier over credentialCommitment | Section 4, AgentPolicy constraint 3 |
| Scope commitment | Poseidon2(permissionBitmask, credentialCommitment) | Section 5, delegation chain linking |
| Nullifier | Poseidon2(credentialCommitment, sessionNonce) | Section 4, AgentPolicy constraint |
| Permission predicate | Bitwise AND via per-bit quadratic constraints | Section 4, AgentPolicy constraint 5 |
| Merkle membership (credentials) | BinaryMerkleRoot(20) with Poseidon2 | Section 3.2, depth 20 |
| Merkle membership (provider keys) | BinaryMerkleRoot(8) with Poseidon2 | Depth 8 tree for provider keys |
| Message binding | Poseidon hash of tool-call payload | Extension of AgentPolicy for C7 |
| Proving system | PLONK with universal setup | Section 3.3, agent/delegation circuits |
| Curve | Baby Jubjub (a=168700, d=168696) embedded in BN254 | Section 3.2 |

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|--------|----------------------|
| Num2Bits(64) × 3 (bitmask, expiry, currentTs) | 192 |
| Poseidon2 (provider key commitment) | 300 |
| BinaryMerkleRoot(8) (provider key Merkle) | 2,400 (8 × ~300 per Poseidon2 level) |
| Poseidon3 (deployment authorization) | 450 |
| EdDSAPoseidonVerifier (provider attestation) | 6,000 |
| Poseidon5 (credential commitment) | 600 |
| EdDSAPoseidonVerifier (operator signature) | 6,000 |
| BinaryMerkleRoot(20) (credential Merkle) | 6,000 (20 × ~300) |
| Bitwise scope check (64 bits) | 128 |
| Cumulative encoding (3 constraints) | 3 |
| LessThan(64) (expiry) | 128 |
| Poseidon (message hash) | 300 |
| Poseidon2 (nullifier) | 300 |
| Poseidon2 (scope commitment) | 300 |
| Poseidon3 (model-operator fingerprint) | 450 |
| **Total** | **~23,550** |

**Proving time target:** <5s (PLONK, agent-class prover). At ~23.5K constraints, PLONK proving on a modern CPU (e.g. Apple M-series, AMD Zen 4) remains well under 5s — comparable to Semaphore's 30K-constraint circuits which prove in ~3s on similar hardware.

**Verification:** On-chain PLONK verification remains ~300K gas (constant regardless of circuit size).

## 7. Concrete deployment scenario

**Stakeholder:** State Employees' Credit Union (SECU), North Carolina — 2.7M members, regulated by NCUA.

**Scenario:** SECU deploys AI agents for member loan servicing. NCUA examiners require proof that only operators **authorized** for approved model tiers (Claude Sonnet 4.6 for routine queries, Claude Opus 4.6 for PII-touching operations) processed member data, without SECU revealing its full agent call log. The regulatory question is: "was the operator contractually and cryptographically authorized to use this model for this call?" — not "did the GPU physically execute these specific weights?" (the latter requires infrastructure-level controls outside the scope of this protocol).

**Enrollment flow:**

1. **Provider setup (Anthropic, one-time):** Anthropic generates a BJJ keypair in an HSM. The public key commitment is inserted into the on-chain provider registry (depth-8 tree). Anthropic publishes the provider public key in a transparency log.

2. **Operator authorization (per operator × model):** When SECU signs a deployment agreement for Claude Sonnet 4.6, Anthropic computes `deploymentAuthorization = Poseidon3(modelHash_sonnet, secuPkAx, secuPkAy)` and signs it. The attestation tuple `(modelHash_sonnet, secuPk, providerSig)` is delivered to SECU via Anthropic's authenticated API dashboard. **A competitor credit union observing or obtaining SECU's attestation tuple cannot use it** — the provider signature is bound to SECU's specific operator key. Separately, Anthropic issues a second attestation for Opus if SECU licenses Opus.

3. **Credential enrollment (SECU):** SECU generates operator BJJ keypairs per deployment environment. For each approved model, SECU constructs a credential commitment using the provider-attested `modelHash` and submits it to the agent Merkle tree. The tree accepts the insertion without on-chain authorization checks — authorization is enforced at proof time.

4. **Runtime proving:** When a Sonnet agent processes a member inquiry, the agent generates a PLONK proof binding `messageHash` (the tool call) to the enrolled credential. The proof embeds both the Anthropic deployment authorization signature and the operator credential signature as private witnesses — the verifier never sees either signature, only confirms they verified inside the circuit.

5. **NCUA audit:** The examiner receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per audited transaction. The examiner verifies each PLONK proof against the on-chain roots. The `modelOperatorFingerprint` confirms the authorized model class (Sonnet vs Opus) without revealing SECU's session tokens, API keys, or full call history. The examiner can confirm "this PII operation was authorized under Opus" without learning which member's data was involved or how many total calls SECU made.

6. **Key rotation:** When SECU rotates API keys (quarterly compliance policy), no re-enrollment is needed — BJJ keypairs are independent of API bearer tokens. Historical proofs remain valid. If SECU rotates their BJJ key, Anthropic issues a new deployment authorization for the new key. If Anthropic releases a new model version, Anthropic issues new `(modelHash, secuPk, providerSig)` tuples and SECU enrolls new credentials; old proofs for the prior version remain verifiable.

**What authorization binding means for the NCUA examiner:** The proof establishes that Anthropic explicitly authorized SECU to use the claimed model for the claimed permission tier. If SECU were to somehow route calls through an unauthorized model while presenting valid Opus proofs, the fraud would lie in SECU's operational layer (analogous to a pharmacy dispensing generic drugs against brand-name prescriptions while holding valid brand licenses). The authorization proof is the cryptographic analogue of a valid prescription — it proves the prescriber authorized the specific drug, not that the pharmacist dispensed it faithfully. Runtime execution integrity is an orthogonal control (achievable via TEE attestation of model loading) that complements but does not replace authorization binding.

**Why the self-enrollment attack is blocked in this scenario:** A rogue fintech company that observes SECU's attestation tuple `(modelHash_sonnet, secuPk, providerSig_secu)` cannot enroll a credential claiming to run Sonnet. The provider signature verifies over `Poseidon3(modelHash_sonnet, secuPkAx, secuPkAy)`, not `Poseidon3(modelHash_sonnet, roguePkAx, roguePkAy)`. The rogue company would need either their own legitimate attestation from Anthropic or an EdDSA forgery.

## 8. Why the baseline cannot match

The baseline (SPIFFE/WIMSE + DPoP + BBS+) fails on the enrollment root-of-trust — and the operator-bound attestation design widens this gap. The comparison below is scoped to **authorization binding** (proving the provider authorized this operator for this model), which is the property this construction claims.

**(a) Non-malleability requires operator-bound provider attestation, not operator self-declaration.** SPIFFE SVIDs bind workload identity to a SPIRE-attested process, but the SPIRE server is operator-controlled. An operator running their own SPIRE deployment can register `spiffe://anthropic.com/models/sonnet-4-6` for a process actually running Opus. The SVID certifies "this process passed attestation on this node," not "the model provider authorized this specific operator for this model identity." BBS+ credentials inherit this weakness: if the issuer (operator) can write any `model_id` claim, selective disclosure of that claim proves nothing about authorization status.

Bolyra's construction eliminates this by requiring an in-circuit EdDSA verification of a provider signature over `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` — a deployment authorization token that binds the model identity to the specific operator's key. The provider key is Merkle-enrolled on-chain. The operator cannot forge this signature (EdDSA unforgeability), cannot substitute their own key for the provider's (provider registry is governance-controlled), and **cannot reuse another operator's attestation** (the signed message includes the operator's public key). The binding is: **provider attests (modelHash, operatorPk) → operator embeds attested modelHash in credential → circuit verifies both signatures and that the operator key in the provider attestation matches the operator key in the credential**. No component of the baseline stack has a mechanism for operator-bound third-party attestation verified inside a selective-disclosure proof.

Note: Neither this construction nor the baseline proves runtime execution fidelity (that the authorized model actually ran at inference time). The baseline's SPIRE node attestation is closer to a runtime binding — it attests a running process — but it attests the process identity, not the model weights, and the operator controls the SPIRE server. Both constructions require a complementary TEE layer for runtime guarantees. The differentiator is that Bolyra's authorization binding is **non-malleable and third-party-rooted** (provider-signed, operator-specific), while the baseline's model identity claim is operator-asserted.

**(b) Key rotation survival.** DPoP ephemeral keys and short-lived SVIDs sever historical bindings on rotation. Bolyra's BJJ keypairs are orthogonal to API bearer tokens; historical proofs verify against archived Merkle roots.

**(c) Cached JWT introspection + DPoP + body_hash: the strongest offline baseline, and why it still falls short.**

The prior version of this section overstated the baseline's dependence on a hot-path AS. draft-ietf-oauth-jwt-introspection-response (§5) allows the AS to issue a **signed JWT introspection response** — a JWT containing token metadata (`active`, `scope`, `client_id`, custom claims like `model_id`) signed by the AS's RSA/EC key. A resource server (verifier) caches this JWT and validates it offline using the AS's published JWKS, removing the AS from the per-call verification path. Combined with RFC 9449 DPoP (which binds each HTTP request to an ephemeral key via `cnf.jkt`) and an `ath` claim (access-token hash), plus a proposed `body_hash` extension binding the request body to the DPoP proof, the baseline can construct:

- **Offline-verifiable token metadata:** The verifier checks the AS's signature on the cached JWT introspection response without contacting the AS.
- **Per-request sender binding:** The DPoP proof ties the request to the ephemeral key whose thumbprint is in the JWT's `cnf.jkt`.
- **Call-content binding:** A `body_hash` in the DPoP proof header binds the specific tool-call payload to the request.

**This is a real construction. It removes the AS from the per-call verification path.** The prior claim that "either the AS sees every hop or binding is not cryptographic" was too strong. We retract it and replace it with a precise decomposition of what the cached-JWT baseline achieves and what it cannot.

**Sub-property (c1): The model-identity claim is AS-asserted, not provider-attested.** The `model_id` claim inside the JWT introspection response is a string placed there by the AS at token issuance time. The AS either (i) trusts the operator's OAuth client registration metadata (the operator self-declared `model_id` when registering the client), or (ii) is itself the model provider (Anthropic operates the AS), in which case the AS directly asserts model identity. In case (i), the claim is operator-asserted and the JWT merely carries a self-declaration with an AS signature — the AS has no mechanism to verify the operator actually runs the claimed model. This is precisely the SPIFFE SVID problem wearing different clothes: a signed assertion of an unverified claim. In case (ii), the AS-as-provider can assert truthfully, but the model-identity binding is then a property of the AS's internal logic, not a cryptographic constraint the verifier can independently audit. The verifier trusts the AS's assertion, which is institutional trust, not cryptographic non-malleability.

In Bolyra, the provider attestation is a cryptographic object (EdDSA signature over `Poseidon3(modelHash, operatorPkAx, operatorPkAy)`) verified inside the PLONK circuit. The verifier does not trust any assertion — the circuit enforces that a provider key enrolled on-chain signed the specific (model, operator) binding. The gap: **cached JWT carries an AS assertion about model identity; Bolyra carries a provider proof of model-operator authorization, verified in zero knowledge.** No JWT claim, however well-signed, constitutes a cryptographic proof that the signing authority verified the model-operator binding at the level of a committed model hash.

**Sub-property (c2): Issuance-time correlation is per-token, not per-deployment.** Removing the AS from the verification path does not remove it from the issuance path. Each time a token is issued or refreshed, the AS observes the full binding: which operator, which model claim, which scope, which DPoP key thumbprint. JWT introspection responses have bounded lifetimes (`exp`); when they expire, the operator must obtain a fresh token, giving the AS another correlation point. Short-lived JWTs (minutes) provide tight revocation but frequent AS contact. Long-lived JWTs (hours/days) reduce AS correlation but delay revocation. The AS accumulates a per-token-issuance log of every (operator, model, scope) tuple.

In Bolyra, the provider signs a deployment authorization **once per (operator, model) pair** at licensing time. No party is contacted at proof time. The provider sees one event — "ACME Corp licensed Sonnet" — not a per-call or per-token-refresh stream. The gap is not AS-in-the-hot-path (the cached JWT eliminates that); the gap is **AS issuance-time correlation granularity**. The baseline's AS learns the operator's activity pattern at token-refresh cadence. Bolyra's provider learns nothing beyond the one-time licensing event.

**Sub-property (c3): DPoP `body_hash` binds content to the bearer, not to the model-identity root of trust.** The DPoP proof with `body_hash` establishes: "the holder of ephemeral key K signed a commitment to request body B." The JWT establishes: "the AS asserts that key K is associated with token T carrying claims {model_id, scope, ...}." The chain is: AS assertion → JWT → DPoP key binding → body hash. The body is bound to the DPoP key, and the DPoP key is bound to the JWT, but the `model_id` claim in the JWT is an AS assertion (see c1). There is no cryptographic path from `body_hash` through to a **provider-signed model commitment**. The verifier sees `body_hash` and trusts that the JWT's `model_id` claim is accurate because the AS signed it — but the AS's basis for that claim is either operator self-declaration or the AS's own internal state, neither of which is a verifiable cryptographic binding.

In Bolyra, constraint 9 (`messageHash = Poseidon(messagePlaintext)`) and constraint 2 (provider attestation over `deploymentAuthorization`) are enforced **in the same circuit**. The proof is atomic: `messageHash` is bound to a credential whose `modelHash` is provider-attested, all within a single PLONK proof. There is no gap between the content-binding layer and the model-identity-binding layer — they share a witness. The baseline's `body_hash` and `model_id` are in different protocol layers (DPoP vs JWT) joined only by the `cnf.jkt` thumbprint matching — a bearer-token binding, not a cryptographic commitment chain rooted in provider attestation.

**Sub-property (c4): Verifier sees full JWT claim set.** The cached JWT introspection response reveals all claims to the verifier: `model_id`, `scope`, `client_id`, `iss`, `sub`, `exp`, `iat`, `cnf`. Selective disclosure of JWT claims requires SD-JWT (draft-ietf-oauth-selective-disclosure-jwt), a separate specification not included in the baseline stack. Even with SD-JWT, the disclosed claims are revealed in cleartext to the verifier — the verifier learns the exact `model_id` string, the exact `scope` string, the issuer identity. There is no mechanism for predicate proofs over undisclosed claims (e.g., proving `permissionBitmask & requiredMask == requiredMask` without revealing the full bitmask).

In Bolyra, the verifier sees only `{agentMerkleRoot, nullifierHash, scopeCommitment, messageHash, modelOperatorFingerprint, requiredScopeMask, currentTimestamp, sessionNonce, providerRegistryRoot}`. The provider's public key, the operator's public key coordinates, the permission bitmask, the expiry, and both signatures are private witnesses — never revealed. The `modelOperatorFingerprint` is a Poseidon3 hash, not a cleartext model identifier. The scope check (constraint 6) is a bitwise predicate evaluated inside the circuit. The baseline cannot match this: JWT claims are revealed to enable verification; Bolyra claims are hidden because verification occurs inside the proof.

**Summary of (c) — what the baseline can and cannot do offline:**

| Property | Cached JWT + DPoP + body_hash | Bolyra ModelInstanceBinding |
|----------|-------------------------------|----------------------------|
| AS removed from per-call verification | Yes (JWT cached, JWKS offline) | Yes (no AS exists; provider signs once) |
| Model-identity claim origin | AS assertion (unverified or self-asserted by operator) | Provider EdDSA signature over (modelHash, operatorPk), verified in-circuit |
| Content-to-model atomic binding | No — body_hash (DPoP layer) and model_id (JWT layer) are in separate protocol layers joined by bearer binding | Yes — messageHash and modelHash share a PLONK witness with provider attestation |
| Issuance-time correlation | Per token refresh (AS sees each issuance) | One-time per (operator, model) licensing event |
| Verifier learns | Full JWT claim set (model_id, scope, iss, sub, exp, cnf in cleartext) | Poseidon3 fingerprint + scope commitment (no cleartext claims) |
| Permission predicate proofs | Not supported (scope is a cleartext string) | Bitwise AND over hidden bitmask (constraint 6) |

The baseline's cached JWT path is a genuine improvement over the hot-path AS model described in RFC 8693 token exchange, and this construction acknowledges that. The residual gap is not "AS in the loop" — it is that the cached JWT carries an **assertion** about model identity, while Bolyra carries a **proof** of model-operator authorization binding rooted in a provider signature verified in zero knowledge. Assertions can be fabricated by any party controlling the AS or the client registration metadata. Proofs require breaking EdDSA or Poseidon collision resistance.

**(d) Permission bitmask predicates.** BBS+ has no native bitwise-AND predicate support. Bolyra enforces `requiredBits[i] * (1 - permBits[i]) === 0` per bit in the arithmetic circuit.

**(e) Provider anonymity.** BBS+ derived proofs reveal the issuer's public key. In Bolyra, the provider's public key is a private input — the verifier sees only `providerRegistryRoot` (confirming the provider is enrolled) and `modelOperatorFingerprint` (confirming the model class), never the provider's actual key or signature. This enables multi-provider deployments where the verifier confirms "an enrolled provider authorized this model" without learning which provider.

**(f) Cross-operator attestation reuse is impossible.** Even if provider attestation tuples leak publicly — through a data breach, careless logging, or deliberate publication — they cannot be weaponized by unauthorized operators. Each attestation is cryptographically bound to the authorized operator's key via `Poseidon3(modelHash, operatorPkAx, operatorPkAy)`. The baseline has no equivalent: a SPIFFE SVID or BBS+ credential containing a `model_id` claim, once observed, can be replayed or re-issued by any party controlling a SPIRE server or credential issuer for that trust domain.
