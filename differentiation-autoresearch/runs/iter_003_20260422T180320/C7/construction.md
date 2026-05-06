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

### Game: MODEL-BIND-FORGE (v2 — public attestation oracle)

**Adversary capabilities:**

- Controls one or more operator BJJ keypairs with legitimately enrolled credentials for model M_adv (e.g. Opus).
- **Has access to all public provider attestation tuples for all models and all other operators.** Specifically, the adversary observes `(modelHash_target, operatorPk_victim, providerSig_victim)` tuples issued to other operators for the target model. This models the worst case where attestation tuples leak or are published.
- Observes arbitrary valid proofs for other models (e.g. Sonnet proofs from other operators).
- Has oracle access to the PLONK prover for their own enrolled credentials.
- Does NOT control the model provider's BJJ signing key (HSM-held).
- Does NOT control the on-chain provider registry (governance-multisig or DAO-controlled).

**Game definition:**

1. Challenger enrolls provider key `providerPk` in the provider registry. Challenger issues operator-bound provider attestations `(modelHash_target, operatorPk_i, providerSig_i)` for a target model M_target to various operators i. Adversary receives all such tuples.
2. Adversary receives their own legitimately enrolled credentials for model M_adv ≠ M_target, including their operator-bound attestation `(modelHash_adv, adversaryPk, providerSig_adv)`. **Crucially, the adversary does NOT receive a provider attestation binding `modelHash_target` to `adversaryPk`** — because the provider never authorized the adversary for M_target.
3. Adversary wins if they produce a valid proof π where `modelOperatorFingerprint` contains `modelHash_target` AND the `operatorPubkeyAx` in the proof corresponds to the adversary's key (i.e., the adversary claims to be running M_target under their own identity).

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
| Deployment authorization | Poseidon3(modelHash, operatorPkAx, operatorPkAy) | New: operator-bound attestation token |
| Provider attestation | EdDSA on Baby Jubjub over deploymentAuthorization | Same primitive as operator signature, now binding (model, operator) |
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

**Proving time target:** <5s (PLONK, agent-class prover). The ~450-constraint increase over the prior estimate (from ~23,100) comes from the additional Poseidon3 computation for `deploymentAuthorization`. At ~23.5K constraints, PLONK proving on a modern CPU (e.g. Apple M-series, AMD Zen 4) remains well under 5s — comparable to Semaphore's 30K-constraint circuits which prove in ~3s on similar hardware.

**Verification:** On-chain PLONK verification remains ~300K gas (constant regardless of circuit size).

## 7. Concrete deployment scenario

**Stakeholder:** State Employees' Credit Union (SECU), North Carolina — 2.7M members, regulated by NCUA.

**Scenario:** SECU deploys AI agents for member loan servicing. NCUA examiners require proof that only approved model instances (Claude Sonnet 4.6 for routine queries, Claude Opus 4.6 for PII-touching operations) processed member data, without SECU revealing its full agent call log.

**Enrollment flow:**

1. **Provider setup (Anthropic, one-time):** Anthropic generates a BJJ keypair in an HSM. The public key commitment is inserted into the on-chain provider registry (depth-8 tree). Anthropic publishes the provider public key in a transparency log.

2. **Operator authorization (per operator × model):** When SECU signs a deployment agreement for Claude Sonnet 4.6, Anthropic computes `deploymentAuthorization = Poseidon3(modelHash_sonnet, secuPkAx, secuPkAy)` and signs it. The attestation tuple `(modelHash_sonnet, secuPk, providerSig)` is delivered to SECU via Anthropic's authenticated API dashboard. **A competitor credit union observing or obtaining SECU's attestation tuple cannot use it** — the provider signature is bound to SECU's specific operator key. Separately, Anthropic issues a second attestation for Opus if SECU licenses Opus.

3. **Credential enrollment (SECU):** SECU generates operator BJJ keypairs per deployment environment. For each approved model, SECU constructs a credential commitment using the provider-attested `modelHash` and submits it to the agent Merkle tree. The tree accepts the insertion without on-chain authorization checks — authorization is enforced at proof time.

4. **Runtime proving:** When a Sonnet agent processes a member inquiry, the agent generates a PLONK proof binding `messageHash` (the tool call) to the enrolled credential. The proof embeds both the Anthropic deployment authorization signature and the operator credential signature as private witnesses — the verifier never sees either signature, only confirms they verified inside the circuit.

5. **NCUA audit:** The examiner receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per audited transaction. The examiner verifies each PLONK proof against the on-chain roots. The `modelOperatorFingerprint` confirms the model class (Sonnet vs Opus) without revealing SECU's session tokens, API keys, or full call history. The examiner can confirm "this PII operation used Opus" without learning which member's data was involved or how many total calls SECU made.

6. **Key rotation:** When SECU rotates API keys (quarterly compliance policy), no re-enrollment is needed — BJJ keypairs are independent of API bearer tokens. Historical proofs remain valid. If SECU rotates their BJJ key, Anthropic issues a new deployment authorization for the new key. If Anthropic releases a new model version, Anthropic issues new `(modelHash, secuPk, providerSig)` tuples and SECU enrolls new credentials; old proofs for the prior version remain verifiable.

**Why the self-enrollment attack is blocked in this scenario:** A rogue fintech company that observes SECU's attestation tuple `(modelHash_sonnet, secuPk, providerSig_secu)` cannot enroll a credential claiming to run Sonnet. The provider signature verifies over `Poseidon3(modelHash_sonnet, secuPkAx, secuPkAy)`, not `Poseidon3(modelHash_sonnet, roguePkAx, roguePkAy)`. The rogue company would need either their own legitimate attestation from Anthropic or an EdDSA forgery.

## 8. Why the baseline cannot match

The baseline (SPIFFE/WIMSE + DPoP + BBS+) fails on the enrollment root-of-trust — and the operator-bound attestation design widens this gap:

**(a) Non-malleability requires operator-bound provider attestation, not operator self-declaration.** SPIFFE SVIDs bind workload identity to a SPIRE-attested process, but the SPIRE server is operator-controlled. An operator running their own SPIRE deployment can register `spiffe://anthropic.com/models/sonnet-4-6` for a process actually running Opus. The SVID certifies "this process passed attestation on this node," not "the model weights match a hash signed by the model provider for this specific operator." BBS+ credentials inherit this weakness: if the issuer (operator) can write any `model_id` claim, selective disclosure of that claim proves nothing about actual model identity.

Bolyra's construction eliminates this by requiring an in-circuit EdDSA verification of a provider signature over `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` — a deployment authorization token that binds the model identity to the specific operator's key. The provider key is Merkle-enrolled on-chain. The operator cannot forge this signature (EdDSA unforgeability), cannot substitute their own key for the provider's (provider registry is governance-controlled), and **cannot reuse another operator's attestation** (the signed message includes the operator's public key). The binding is: **provider attests (modelHash, operatorPk) → operator embeds attested modelHash in credential → circuit verifies both signatures and that the operator key in the provider attestation matches the operator key in the credential**. No component of the baseline stack has a mechanism for operator-bound third-party attestation verified inside a selective-disclosure proof.

**(b) Key rotation survival.** DPoP ephemeral keys and short-lived SVIDs sever historical bindings on rotation. Bolyra's BJJ keypairs are orthogonal to API bearer tokens; historical proofs verify against archived Merkle roots.

**(c) No AS in the verification path.** BBS+ selective disclosure can operate offline, but without an AS enforcing the model-identity claim at issuance, the claim is operator-asserted. Adding an AS to enforce it re-introduces the correlation problem (AS sees every call). Bolyra's provider attestation is offline — the provider signs a deployment authorization once per (operator, model) pair, not per call. No party beyond the prover and verifier participates at proof time.

**(d) Permission bitmask predicates.** BBS+ has no native bitwise-AND predicate support. Bolyra enforces `requiredBits[i] * (1 - permBits[i]) === 0` per bit in the arithmetic circuit.

**(e) Provider anonymity.** BBS+ derived proofs reveal the issuer's public key. In Bolyra, the provider's public key is a private input — the verifier sees only `providerRegistryRoot` (confirming the provider is enrolled) and `modelOperatorFingerprint` (confirming the model class), never the provider's actual key or signature. This enables multi-provider deployments where the verifier confirms "an enrolled provider attested this model" without learning which provider.

**(f) Cross-operator attestation reuse is impossible.** Even if provider attestation tuples leak publicly — through a data breach, careless logging, or deliberate publication — they cannot be weaponized by unauthorized operators. Each attestation is cryptographically bound to the authorized operator's key via `Poseidon3(modelHash, operatorPkAx, operatorPkAy)`. The baseline has no equivalent: a SPIFFE SVID or BBS+ credential containing a `model_id` claim, once observed, can be replayed or re-issued by any party controlling a SPIRE server or credential issuer for that trust domain.
