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
- `providerSigR8x`, `providerSigR8y`, `providerSigS`: Provider EdDSA signature over `modelHash`
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

2. **Provider attestation of modelHash** (root-of-trust gadget):
   - `providerKeyCommitment = Poseidon2(providerPubkeyAx, providerPubkeyAy)`
   - `BinaryMerkleRoot(8)` with `providerKeyCommitment` as leaf MUST produce `providerRegistryRoot` — proving the provider key is enrolled on-chain.
   - `EdDSAPoseidonVerifier(providerPubkeyAx, providerPubkeyAy, providerSigR8x, providerSigR8y, providerSigS, modelHash)` — proving the model provider signed this specific modelHash.

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

**Model attestation (per model release):**

- At model packaging time, Anthropic computes `modelHash = Poseidon(model_identifier_canonical)` where `model_identifier_canonical` is a deterministic encoding of the model name, version, and weight checksum (e.g. `"claude-sonnet-4-6:sha256:ab3f..."`).
- Anthropic signs `modelHash` with the provider BJJ key: `providerSig = EdDSA.Sign(providerSecret, modelHash)`.
- The `(modelHash, providerSig, providerPk)` tuple is published to a model attestation registry (append-only log, or IPFS CID pinned on-chain). Operators retrieve this tuple when enrolling credentials.

**Credential enrollment (per operator × model):**

- Operator generates their own BJJ keypair.
- Operator constructs `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiry)` using a provider-attested `modelHash`.
- Operator signs `credentialCommitment` with their BJJ key.
- Operator submits `credentialCommitment` for insertion into the agent Merkle tree.
- At proving time, operator supplies both signatures (provider over modelHash, operator over credentialCommitment) as private inputs.

### Public signal layout (PLONK, 8 signals)

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

### Game: MODEL-BIND-FORGE

**Adversary capabilities:**

- Controls one or more operator BJJ keypairs with legitimately enrolled credentials for model M_adv (e.g. Opus).
- Observes arbitrary valid proofs for other models (e.g. Sonnet proofs from other operators).
- Has oracle access to the PLONK prover for their own enrolled credentials.
- Does NOT control the model provider's BJJ signing key (HSM-held).
- Does NOT control the on-chain provider registry (governance-multisig or DAO-controlled).

**Game definition:**

1. Challenger enrolls provider key `providerPk` in the provider registry. Challenger issues provider attestations `(modelHash_target, providerSig_target)` for a target model M_target.
2. Adversary receives enrolled credentials for model M_adv ≠ M_target, including `(modelHash_adv, providerSig_adv)`.
3. Adversary wins if they produce a valid proof π where `modelOperatorFingerprint` contains `modelHash_target` (i.e., the proof claims the call was made by M_target).

**Winning condition:** Adversary produces (π, publicSignals) such that:
- PLONK.Verify(vk, publicSignals, π) = 1
- agentMerkleRoot ∈ rootHistoryBuffer
- providerRegistryRoot matches on-chain state
- The `modelHash` committed inside `credentialCommitment` equals `modelHash_target`

### Root-of-trust threat model addition

**Enrollment integrity game: PROVIDER-FORGE**

1. Adversary controls operator keys but not the provider BJJ key.
2. Adversary attempts to enroll a credential with `modelHash_target` without possessing a valid `providerSig` over `modelHash_target` from an enrolled provider key.
3. Adversary wins if they produce a valid proof that passes constraint 2 (provider attestation verification + provider key Merkle membership).

**Why self-attestation is eliminated:** Constraint 2 requires the provider signature to verify inside the circuit against a provider key that is itself Merkle-included in `providerRegistryRoot`. The operator cannot:
- Forge a provider signature (EdDSA unforgeability under DL on Baby Jubjub).
- Insert their own key into the provider registry (on-chain governance controls insertion).
- Substitute a different modelHash while reusing a valid provider signature (EdDSA binds the signature to the exact message).

This is the critical difference from OAuth `client_id`: the binding from model identity to cryptographic credential is attested by the model provider's key, not self-declared by the operator. The provider key is enrolled on-chain with the same trust root as the agent Merkle tree. An operator claiming "I am running Sonnet" must present a Sonnet-specific provider signature — possessing an Opus provider signature does not help.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| Label | Assumption |
|-------|------------|
| A1 | Collision resistance of Poseidon over BN254 scalar field |
| A2 | Discrete logarithm hardness on Baby Jubjub (EdDSA unforgeability) |
| A3 | Knowledge soundness of PLONK in the algebraic group model + ROM |
| A4 | Collision resistance of Poseidon5 (credential commitment binding) |

### Reduction sketch for MODEL-BIND-FORGE

**Theorem:** Any PPT adversary winning MODEL-BIND-FORGE with non-negligible probability breaks A1, A2, or A3.

**Proof sketch:**

Given adversary A that wins MODEL-BIND-FORGE, extract witness via A3 (PLONK knowledge soundness). The extracted witness contains `(modelHash, operatorPk, permissionBitmask, expiry, providerPk, providerSig, operatorSig, merkleProof, providerMerkleProof)`.

**Case 1:** Extracted `modelHash ≠ modelHash_target` but `modelOperatorFingerprint` matches a fingerprint containing `modelHash_target`. Then `Poseidon3(modelHash, ...) = Poseidon3(modelHash_target, ...)` with `modelHash ≠ modelHash_target` — this is a Poseidon collision, breaking A1.

**Case 2:** Extracted `modelHash = modelHash_target` and `providerSig` verifies over `modelHash_target` under some `providerPk`. Two sub-cases:

- **2a:** `providerPk` is enrolled in provider registry (Merkle proof valid against `providerRegistryRoot`). Then `providerSig` is a valid EdDSA signature on `modelHash_target` under an enrolled provider key. Since the adversary does not control any enrolled provider key, this is an EdDSA forgery — breaks A2.

- **2b:** `providerPk` is NOT enrolled but the Merkle proof still verifies. Then `Poseidon2(providerPkAx, providerPkAy)` appears at a leaf position that hashes to the correct `providerRegistryRoot` despite never being inserted. This is a Poseidon collision or second-preimage on the Merkle path — breaks A1.

**Case 3:** Extracted `credentialCommitment` is in the agent Merkle tree but was enrolled with `modelHash_adv ≠ modelHash_target`, yet the extracted credential commitment equals `Poseidon5(modelHash_target, ...)`. Then `Poseidon5(modelHash_adv, opPk, ...) = Poseidon5(modelHash_target, opPk', ...)` — Poseidon5 collision, breaks A4.

### Reduction sketch for PROVIDER-FORGE

Same structure as Case 2 above. The adversary must either forge an EdDSA signature (breaks A2) or produce a fraudulent Merkle inclusion proof (breaks A1).

### Key rotation survival

Operator API key rotation does not affect the construction because:
- The BJJ keypair used for credential signing is independent of any API bearer token or session key.
- Historical proofs reference a `credentialCommitment` that was enrolled under a specific BJJ public key. The Merkle root at verification time includes this commitment. Rotating the API key does not alter the Merkle tree.
- If the operator rotates their BJJ key, they enroll a new credential with the new key. Old proofs remain valid against old Merkle roots stored in the 30-entry root history buffer. For long-term archival, the verifier stores the `agentMerkleRoot` from the proof at verification time.

### Provider key rotation

- Provider rotates by enrolling a new BJJ key in the provider registry and revoking the old one (new root excludes old key commitment).
- Historical proofs that used the old provider key remain valid: at verification time, the `providerRegistryRoot` public input matched the on-chain root that included the old key. Archival verifiers store the `providerRegistryRoot` alongside the proof.
- New credentials must use the new provider key's attestation.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Credential commitment | Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry) | Section 4, AgentPolicy circuit |
| Provider key commitment | Poseidon2(providerPkAx, providerPkAy) | Analogous to identity commitment (Section 4, HumanUniqueness) |
| Provider attestation | EdDSA on Baby Jubjub over modelHash | Same primitive as operator signature |
| Operator signature | EdDSAPoseidonVerifier over credentialCommitment | Section 4, AgentPolicy constraint 3 |
| Scope commitment | Poseidon2(permissionBitmask, credentialCommitment) | Section 5, delegation chain linking |
| Nullifier | Poseidon2(credentialCommitment, sessionNonce) | Section 4, AgentPolicy constraint |
| Permission predicate | Bitwise AND via per-bit quadratic constraints | Section 4, AgentPolicy constraint 5 |
| Merkle membership (credentials) | BinaryMerkleRoot(20) with Poseidon2 | Section 3.2, depth 20 |
| Merkle membership (provider keys) | BinaryMerkleRoot(8) with Poseidon2 | New: depth 8 tree for provider keys |
| Message binding | Poseidon hash of tool-call payload | Extension of AgentPolicy for C7 |
| Proving system | PLONK with universal setup | Section 3.3, agent/delegation circuits |
| Curve | Baby Jubjub (a=168700, d=168696) embedded in BN254 | Section 3.2 |

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|--------|----------------------|
| Num2Bits(64) × 3 (bitmask, expiry, currentTs) | 192 |
| Poseidon2 (provider key commitment) | 300 |
| BinaryMerkleRoot(8) (provider key Merkle) | 2,400 (8 × ~300 per Poseidon2 level) |
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
| **Total** | **~23,100** |

**Proving time target:** <5s (PLONK, agent-class prover). The ~8,400 constraint increase over the prior estimate (from ~14,750) comes from the provider attestation gadget (EdDSA verification + depth-8 Merkle proof). At 23K constraints, PLONK proving on a modern CPU (e.g. Apple M-series, AMD Zen 4) remains well under 5s — comparable to Semaphore's 30K-constraint circuits which prove in ~3s on similar hardware.

**Verification:** On-chain PLONK verification remains ~300K gas (constant regardless of circuit size).

## 7. Concrete deployment scenario

**Stakeholder:** State Employees' Credit Union (SECU), North Carolina — 2.7M members, regulated by NCUA.

**Scenario:** SECU deploys AI agents for member loan servicing. NCUA examiners require proof that only approved model instances (Claude Sonnet 4.6 for routine queries, Claude Opus 4.6 for PII-touching operations) processed member data, without SECU revealing its full agent call log.

**Enrollment flow:**

1. **Provider setup (Anthropic, one-time):** Anthropic generates a BJJ keypair in an HSM. The public key commitment is inserted into the on-chain provider registry (depth-8 tree). Anthropic publishes `(modelHash, providerSig)` pairs for each released model to an attestation registry.

2. **Operator enrollment (SECU):** SECU generates operator BJJ keypairs per deployment environment. For each approved model, SECU retrieves Anthropic's `(modelHash, providerSig)` and constructs a credential commitment. SECU submits credentials to the agent Merkle tree.

3. **Runtime proving:** When a Sonnet agent processes a member inquiry, the agent generates a PLONK proof binding `messageHash` (the tool call) to the enrolled credential. The proof embeds the Anthropic provider attestation as a private witness — the verifier never sees the signature itself, only confirms it verified inside the circuit.

4. **NCUA audit:** The examiner receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per audited transaction. The examiner verifies each PLONK proof against the on-chain roots. The `modelOperatorFingerprint` confirms the model class (Sonnet vs Opus) without revealing SECU's session tokens, API keys, or full call history. The examiner can confirm "this PII operation used Opus" without learning which member's data was involved or how many total calls SECU made.

5. **Key rotation:** When SECU rotates API keys (quarterly compliance policy), no re-enrollment is needed — BJJ keypairs are independent of API bearer tokens. Historical proofs remain valid. If Anthropic releases a new model version, Anthropic issues a new `(modelHash, providerSig)` and SECU enrolls new credentials; old proofs for the prior version remain verifiable.

## 8. Why the baseline cannot match

The baseline (SPIFFE/WIMSE + DPoP + BBS+) fails on the enrollment root-of-trust — the exact gap this iteration addresses:

**(a) Non-malleability requires provider attestation, not operator self-declaration.** SPIFFE SVIDs bind workload identity to a SPIRE-attested process, but the SPIRE server is operator-controlled. An operator running their own SPIRE deployment can register `spiffe://anthropic.com/models/sonnet-4-6` for a process actually running Opus. The SVID certifies "this process passed attestation on this node," not "the model weights match a hash signed by the model provider." BBS+ credentials inherit this weakness: if the issuer (operator) can write any `model_id` claim, selective disclosure of that claim proves nothing about actual model identity.

Bolyra's construction eliminates this by requiring an in-circuit EdDSA verification of a provider signature over `modelHash`, where the provider key is Merkle-enrolled on-chain. The operator cannot forge this signature (EdDSA unforgeability) and cannot substitute their own key for the provider's (provider registry is governance-controlled, not operator-controlled). The binding is: **provider attests modelHash → operator embeds attested modelHash in credential → circuit verifies both signatures**. No component of the baseline stack has a mechanism for a third-party (non-operator, non-AS) attestation to be verified inside a selective-disclosure proof.

**(b) Key rotation survival.** DPoP ephemeral keys and short-lived SVIDs sever historical bindings on rotation. Bolyra's BJJ keypairs are orthogonal to API bearer tokens; historical proofs verify against archived Merkle roots.

**(c) No AS in the verification path.** BBS+ selective disclosure can operate offline, but without an AS enforcing the model-identity claim at issuance, the claim is operator-asserted. Adding an AS to enforce it re-introduces the correlation problem (AS sees every call). Bolyra's provider attestation is offline — the provider signs `modelHash` once per model release, not per call. No party beyond the prover and verifier participates at proof time.

**(d) Permission bitmask predicates.** BBS+ has no native bitwise-AND predicate support. Bolyra enforces `requiredBits[i] * (1 - permBits[i]) === 0` per bit in the arithmetic circuit.

**(e) Provider anonymity.** BBS+ derived proofs reveal the issuer's public key. In Bolyra, the provider's public key is a private input — the verifier sees only `providerRegistryRoot` (confirming the provider is enrolled) and `modelOperatorFingerprint` (confirming the model class), never the provider's actual key or signature. This enables multi-provider deployments where the verifier confirms "an enrolled provider attested this model" without learning which provider.
