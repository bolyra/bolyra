# How Bolyra Maps to IETF Agent Authentication

**Position Paper: Bolyra as a Privacy Extension to draft-klrc-aiagent-auth-01**

Viswanadha Pratap Kondoju, Bolyra
April 2026

---

## 1. Background

The IETF draft-klrc-aiagent-auth-01 (Kline, Raghavan, Chatterjee; backed by AWS, Zscaler, Ping Identity, OpenAI) establishes a framework for authenticating AI agents acting on behalf of users. It defines agent tokens, delegation semantics, scope-restricted authorization, and lifecycle management. However, the draft relies on bearer-token and OAuth-derived constructs that expose authorization metadata to relying parties. There is no mechanism for selective disclosure, and delegation chains reveal their full structure to verifiers.

Bolyra (draft-bolyra-mutual-zkp-auth-00) is a mutual zero-knowledge proof authentication protocol for human and AI agent identities. This document maps Bolyra's primitives onto the KLRC framework and identifies where Bolyra provides privacy properties that the existing draft cannot express.

## 2. Concept Mapping

| KLRC Concept (draft-klrc-aiagent-auth-01) | Bolyra Equivalent (draft-bolyra-mutual-zkp-auth-00) | Relationship |
|---|---|---|
| **Agent Token** (bearer credential identifying the agent) | **Agent Credential Commitment** — Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp) stored as a Merkle leaf | Bolyra replaces the opaque bearer token with a hiding commitment; the verifier learns that a valid credential exists but not its contents |
| **User Identity / Principal** | **Human Identity Commitment** — Poseidon2(Ax, Ay) derived from an EdDSA secret on Baby Jubjub | The human principal is represented as a Merkle leaf; group membership is proved without revealing which leaf |
| **Auth Flow / Token Exchange** | **Mutual Handshake** — parallel Groth16 (human) + PLONK (agent) proofs bound to a shared session nonce, verified atomically on-chain | Replaces a multi-round token exchange with a single-round, dual-proof verification step |
| **Scope / Permissions** | **Identity-Bound Scope Commitment** — Poseidon2(permissionBitmask, credentialCommitment) | Permissions are committed, not disclosed; the verifier checks that requiredScopeMask bits are satisfied inside the ZK circuit |
| **Delegation / Token Chaining** | **Composable Delegation Chain** — each hop narrows permissions via bitwise AND and produces a PLONK proof linking scopeCommitment_i to scopeCommitment_{i+1} | Each delegation hop is privacy-preserving; the verifier sees only that narrowing occurred, not the actual bitmask at any hop |
| **Token Expiry / Revocation** | **On-chain expiry check** (expiryTimestamp > currentTimestamp, enforced in-circuit) + **nullifier-based revocation** (nullifier mapping on the registry contract) | Expiry is enforced cryptographically inside the proof; revocation uses deterministic nullifiers rather than token introspection |
| **Agent Identity Metadata** (model, operator, capabilities) | **Private circuit inputs** (modelHash, operatorPubkey, permissionBitmask) — never revealed to the verifier | All agent metadata is hidden; only the scope commitment and nullifier are public outputs |

## 3. What Bolyra Adds

The KLRC draft provides a sound authorization architecture but inherits the metadata exposure characteristics of OAuth 2.0. Bolyra addresses three gaps:

**3.1 Selective Disclosure of Permissions.** In KLRC, a relying party inspecting an agent token learns the full scope string. In Bolyra, the agent proves `(permissionBitmask & requiredScopeMask) == requiredScopeMask` inside the ZK circuit. The relying party learns only that the required bits are set, not what other permissions exist. This is the identity-bound scope commitment primitive: the public output is Poseidon2(permissionBitmask, credentialCommitment), which is opaque without knowledge of the preimage.

**3.2 Privacy-Preserving Delegation Chains.** KLRC delegation produces a chain of tokens whose structure (depth, participants, scope at each hop) is visible to the final relying party. Bolyra's delegation circuit proves that each hop's scope commitment is a valid narrowing of the previous hop's commitment, without revealing the bitmask at any intermediate step. The verifier checks `(delegatorScope & delegateeScope) == delegateeScope` in-circuit and sees only the final scope commitment.

**3.3 Mutual Authentication with Unlinkability.** KLRC authenticates the agent to the resource server but does not define mutual authentication where both the human and agent prove identity to each other simultaneously. Bolyra's handshake binds a human's Groth16 proof and an agent's PLONK proof to a shared session nonce, verified atomically. The human's nullifier provides Sybil resistance within a scope without cross-scope linkability.

## 4. Proposed Integration Path

Bolyra is not a replacement for draft-klrc-aiagent-auth-01. It is a **privacy layer** that can compose with the KLRC framework in two modes:

**Mode A — Companion Specification.** Define a new token type within the KLRC framework where the agent token is a ZK proof bundle (proof bytes, public signals, verification key identifier) rather than a signed JWT. The KLRC auth flow proceeds as specified, but the token introspection endpoint verifies a PLONK proof instead of checking a signature. This requires no changes to KLRC's delegation semantics; it only changes the token format.

**Mode B — Privacy Extension (Recommended).** Register a `proof_method` parameter in the KLRC auth request that signals the relying party supports ZKP-based credential presentation. When both parties support it, the flow upgrades to Bolyra's mutual handshake. When either party does not, the flow falls back to standard KLRC bearer tokens. This preserves backward compatibility while enabling progressive adoption.

In either mode, the on-chain registry (Bolyra Section 3.1) serves as the trust anchor for Merkle root validity and nonce freshness, analogous to the token introspection endpoint in OAuth-based systems.

## 5. Open Questions for the Working Group

1. **Proof format standardization.** Should ZKP-based agent tokens use a CBOR or JSON encoding for the proof bundle? Alignment with draft-ietf-cose-bls-key-representations may be appropriate.
2. **Ceremony trust model.** Groth16 requires a circuit-specific Phase 2 ceremony. Can the KLRC framework accommodate proving systems that require a one-time trusted setup, or should the spec mandate universal-setup systems (PLONK) only?
3. **On-chain vs. off-chain verification.** Bolyra's current spec assumes on-chain verification for atomicity guarantees. A purely off-chain variant (with a centralized nonce service) would lower deployment barriers but weaken the trust model.
4. **Nullifier privacy across scopes.** Bolyra's nullifier construction (Poseidon2(scope, secret)) prevents cross-scope linkability. Should the KLRC spec define a similar unlinkability requirement for agent identifiers across resource servers?

---

*This document is intended for discussion within the IETF community and does not constitute a standard. Bolyra is an open-source protocol; specification and reference implementation are available at https://github.com/saneGuy/bolyra.*
