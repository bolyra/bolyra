# How Bolyra Maps to IETF Agent Authentication

**Position Paper: Bolyra as a Privacy Extension to draft-klrc-aiagent-auth-01**

Viswanadha Pratap Kondoju, Bolyra
May 2026

---

## 1. Background

The IETF draft-klrc-aiagent-auth-01 (Kline, Raghavan, Chatterjee; backed by AWS, Zscaler, Ping Identity, OpenAI) establishes a framework for authenticating AI agents acting on behalf of users. It defines agent tokens, delegation semantics, scope-restricted authorization, and lifecycle management. However, the draft relies on bearer-token and OAuth-derived constructs that expose authorization metadata to relying parties. There is no mechanism for selective disclosure, and delegation chains reveal their full structure to verifiers.

Bolyra (draft-bolyra-mutual-zkp-auth-01) is a mutual zero-knowledge proof authentication protocol for human and AI agent identities. This document maps Bolyra's primitives onto the KLRC framework and identifies where Bolyra provides privacy properties that the existing draft cannot express.

## 2. Concept Mapping

| KLRC Concept (draft-klrc-aiagent-auth-01) | Bolyra Equivalent (draft-bolyra-mutual-zkp-auth-01) | Relationship |
|---|---|---|
| **Agent Token** (bearer credential identifying the agent) | **Agent Credential Commitment** — Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp) stored as a Merkle leaf | Bolyra replaces the opaque bearer token with a hiding commitment; the verifier learns that a valid credential exists but not its contents |
| **User Identity / Principal** | **Human Identity Commitment** — Poseidon2(Ax, Ay) derived from an EdDSA secret on Baby Jubjub | The human principal is represented as a Merkle leaf; group membership is proved without revealing which leaf |
| **Auth Flow / Token Exchange** | **Mutual Handshake** — parallel Groth16 (human) + PLONK (agent) proofs bound to a shared session nonce, verified atomically on-chain | Replaces a multi-round token exchange with a single-round, dual-proof verification step |
| **Scope / Permissions** | **Identity-Bound Scope Commitment** — Poseidon2(permissionBitmask, credentialCommitment) | Permissions are committed, not disclosed; the verifier checks that requiredScopeMask bits are satisfied inside the ZK circuit |
| **Delegation / Token Chaining** | **Composable Delegation Chain** — each hop narrows permissions via bitwise AND and produces a PLONK proof linking scopeCommitment_i to scopeCommitment_{i+1} | Each delegation hop is privacy-preserving; the verifier sees only that narrowing occurred, not the actual bitmask at any hop |
| **Token Expiry / Revocation** | **On-chain expiry check** (expiryTimestamp > currentTimestamp, enforced in-circuit) + **nullifier-based revocation** (nullifier mapping on the registry contract) | Expiry is enforced cryptographically inside the proof; revocation uses deterministic nullifiers rather than token introspection |
| **Agent Identity Metadata** (model, operator, capabilities) | **Private circuit inputs** (modelHash, operatorPubkey, permissionBitmask) — never revealed to the verifier | All agent metadata is hidden; only the scope commitment and nullifier are public outputs |

## 3. What Bolyra Adds

The KLRC draft provides a sound authorization architecture but inherits the metadata exposure characteristics of OAuth 2.0. Under adversarial scrutiny (5-persona differentiation-autoresearch, 2026-04-22), two Bolyra properties cleared the bar that no configuration of KLRC + RFC 7662 + RFC 8693 + RFC 8707 + DPoP + WIMSE + BBS+ can match. These are the load-bearing contributions to the WG.

**3.1 Cryptographic Model-Instance Binding (primary contribution, 9/10 under adversarial review).** KLRC authenticates the agent's registered application (`client_id`), but not *which model instance* produced a given call. Bolyra binds `(modelHash, operator_pk, permission_bitmask, messageHash)` to each RS invocation as a single PLONK proof. The verifier learns only this tuple — not the API key, not the operator's full session history, not which call was which model. Non-malleability survives under adversarial-operator attacks: an operator holding an Opus key cannot forge a proof saying Sonnet made the call. Provider anonymity survives under rogue-RS attacks: the Anthropic-signed provider key is a private input; the verifier sees only the fingerprint registry root. The load-bearing deployment is a regulated CISO proving to an NCUA or FDA examiner that only approved models touched regulated data, without revealing which call was which model. **This property cannot be expressed in KLRC's current token model.**

Scope limitation: Bolyra proves *authorization* binding, not *execution* binding. Runtime model substitution after proof generation requires TEE/hardware attestation and is out of scope for a pure-ZK construction. Closing that gap is a "Bolyra + TEE" companion track, not a claim on the KLRC spec.

**3.2 AS-Blind Cross-Scope Unlinkability (secondary contribution, 8/10).** In KLRC, the AS sees every agent-to-RS introspection call by construction. Pairwise subject identifiers help against RS-vs-RS collusion but do not hide the (agent, RS) pair from the AS itself. Bolyra's per-scope nullifier construction — `nullifier = Poseidon2(scope_id, secret)` — plus local post-enrollment proof generation means the AS never participates in the per-scope authorization path. The load-bearing deployment is a credit-union-as-AS that must not reconstruct its members' merchant graph under GLBA Reg P. **This property cannot be expressed in KLRC's current flow model.**

**3.3 Selective Disclosure of Permissions.** In KLRC, a relying party inspecting an agent token learns the full scope string. In Bolyra, the agent proves `(permissionBitmask & requiredScopeMask) == requiredScopeMask` inside the ZK circuit. Note: a well-configured KLRC AS with per-RS scope policies can approximate this. The stronger property here is that Bolyra removes the AS from the hot path entirely, which composes with §3.2.

**3.4 Privacy-Preserving Delegation Chains.** KLRC delegation produces a chain of tokens whose structure (depth, participants, scope at each hop) is visible to the final relying party. Bolyra's delegation circuit proves that each hop's scope commitment is a valid narrowing of the previous hop's commitment, without revealing the bitmask at any intermediate step. Applicability: narrow-but-real regulated scenarios (HIPAA chain of custody, cross-border financial delegation).

**3.5 Mutual Authentication.** KLRC authenticates the agent to the resource server but does not define mutual authentication where both the human and agent prove identity to each other simultaneously. Bolyra's handshake binds a human's Groth16 proof and an agent's PLONK proof to a shared session nonce, verified atomically.

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

*This document is intended for discussion within the IETF community and does not constitute a standard. Bolyra is an open-source protocol; specification and reference implementation are available at https://github.com/saneGuy/identityos (repository rename to `bolyra` pending).*
