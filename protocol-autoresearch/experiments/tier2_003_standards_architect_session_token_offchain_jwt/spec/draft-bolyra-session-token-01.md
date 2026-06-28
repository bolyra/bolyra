---
title: "Bolyra Session Token: A JWT Profile for Verified ZKP Handshakes"
abbrev: "bolyra-session-token"
docname: draft-bolyra-session-token-01
date: 2026-06-20
category: std
ipr: trust200902
area: Security
workgroup: Bolyra Protocol
keyword: [JWT, ZKP, session, identity, handshake]
author:
  - fullname: Viswa Swaminathan
    organization: ZKProva Inc.
    email: viswa@bolyra.ai
normative:
  RFC7519:
  RFC7515:
  RFC7517:
  RFC9449:
informative:
  BOLYRA-AUTH:
    title: "Mutual ZKP Authentication for Human-Agent Handshakes"
    target: draft-bolyra-mutual-zkp-auth-01
---

# Abstract

This document defines a JWT profile — `bolyra+jwt` — that encodes the
verified result of a Bolyra mutual ZKP handshake as a compact,
offchain-verifiable token. The profile maps handshake outputs
(humanNullifier, agentNullifier, scopeCommitment, sessionNonce) to
registered and private JWT claims under a `bolyra.*` namespace, defines
a `bolyra+jwt` media type for the `typ` header parameter, and specifies
an optional `vtx` JOSE header carrying the on-chain verification
transaction hash. Nonce binding follows OAuth 2.0 DPoP semantics
[RFC9449] to prevent replay across sessions.

# Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

# 1. Introduction

The Bolyra mutual ZKP authentication protocol [BOLYRA-AUTH] produces a
set of public signals after a successful handshake between a human
identity holder and an AI agent credential. On-chain verification
confirms the cryptographic validity of both zero-knowledge proofs, but
subsequent interactions between the relying party and the
human-agent pair should not require repeated on-chain queries.

This document defines a JWT profile that encodes the verified handshake
result as a signed JSON Web Token [RFC7519]. Relying parties can verify
the token using standard JWT libraries and the issuer's public key,
without any blockchain interaction.

## 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

# 2. Terminology

- **Handshake Result**: The set of public outputs from a successful
  Bolyra mutual ZKP verification: humanNullifier, agentNullifier,
  scopeCommitment, sessionNonce, and verificationTimestamp.

- **Session Token**: A signed JWT encoding the Handshake Result,
  issued by the verifying party after on-chain confirmation.

- **Issuer**: The entity that performed on-chain verification and
  signs the session token. Identified by the `iss` claim.

- **Relying Party (RP)**: Any downstream service that consumes the
  session token to authorize requests without repeating on-chain
  verification.

- **Verification Transaction (vtx)**: The on-chain transaction hash
  that confirmed the handshake proofs. Carried in the JOSE header.

# 3. JOSE Header

The JOSE protected header for a `bolyra+jwt` token MUST contain:

| Parameter | Value | Required |
|-----------|-------|----------|
| `alg` | `ES256` or `EdDSA` | REQUIRED |
| `typ` | `bolyra+jwt` | REQUIRED |
| `vtx` | Base16 (hex) encoded on-chain tx hash | OPTIONAL |

Example:

```json
{
  "alg": "EdDSA",
  "typ": "bolyra+jwt",
  "vtx": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
}
```

## 3.1. Algorithm Selection

Issuers SHOULD use `EdDSA` with curve `Ed25519` for new deployments.
`ES256` (ECDSA with P-256) is permitted for compatibility with existing
OAuth 2.0 infrastructure.

## 3.2. Verification Transaction Header (`vtx`)

When the handshake was verified on-chain, the issuer SHOULD include the
`vtx` header parameter containing the hex-encoded transaction hash
(with `0x` prefix for EVM chains). This enables auditors to
independently verify the on-chain proof without trusting the issuer.

Relying parties MUST NOT treat the `vtx` header as a substitute for
signature verification. The `vtx` value is informational and does not
affect JWT validation.

# 4. JWT Claims

## 4.1. Registered Claims

| Claim | Source | Description | Required |
|-------|--------|-------------|----------|
| `sub` | humanNullifier | The nullifier hash derived from the human's identity commitment. Hex-encoded. | REQUIRED |
| `iss` | verifier identity | URI or DID of the entity that verified the handshake and signed the token. | REQUIRED |
| `iat` | verificationTimestamp | Unix timestamp of the on-chain verification. | REQUIRED |
| `exp` | iat + ttl | Expiration time. MUST NOT exceed `iat + 900` (15 minutes). | REQUIRED |
| `jti` | random UUID | Unique token identifier for replay detection. | REQUIRED |

## 4.2. Private Claims (bolyra.* namespace)

All Bolyra-specific claims use the `bolyra.` prefix to avoid collision
with other JWT profiles.

| Claim | Source | Description | Required |
|-------|--------|-------------|----------|
| `bolyra.agn` | agentNullifier | Nullifier hash of the agent credential. Hex-encoded. | REQUIRED |
| `bolyra.scp` | scopeCommitment | Hash commitment to the delegated permission scope. Hex-encoded. | REQUIRED |
| `bolyra.vtx` | on-chain tx hash | Redundant with header `vtx`; included in payload for claim-level access. | OPTIONAL |
| `bolyra.nonce` | sessionNonce | The nonce that was bound into both ZK proofs during handshake. | REQUIRED |
| `bolyra.perm` | permissions bitmask | 8-bit cumulative permission encoding (see Bolyra spec). Integer 0-255. | OPTIONAL |

## 4.3. Nonce Binding and Replay Prevention

The `bolyra.nonce` claim carries the `sessionNonce` that was committed
into both the HumanUniqueness and AgentPolicy proofs during handshake.
This value MUST be unique per handshake session.

Relying parties MUST maintain a nonce store and reject any token whose
`bolyra.nonce` has been seen before within the token's validity window.

### 4.3.1. DPoP Integration (RFC 9449)

When used within an OAuth 2.0 flow, the `bolyra.nonce` SHOULD be bound
to the DPoP `nonce` parameter as defined in Section 4 of [RFC9449].
The authorization server provides the DPoP nonce; the client includes
it as the `sessionNonce` input to `proveHandshake()`, creating a
cryptographic binding between the DPoP proof and the ZKP handshake.

# 5. Token Lifecycle

## 5.1. Issuance

1. The verifier calls `verifyHandshake(humanProof, agentProof, nonce)`
   on-chain or via a local verifier.
2. On success, the verifier constructs a JWT with the claims defined
   in Section 4 and signs it with its private key.
3. The signed token is returned to the requesting party.

## 5.2. Verification

A relying party verifying a `bolyra+jwt` token MUST:

1. Verify the JWS signature using the issuer's public key.
2. Confirm `typ` header equals `bolyra+jwt`.
3. Confirm `alg` is `ES256` or `EdDSA`.
4. Validate `exp` has not passed and `iat` is not in the future.
5. Validate `iss` matches an expected issuer.
6. Confirm `bolyra.nonce` has not been previously consumed.
7. Confirm `sub`, `bolyra.agn`, `bolyra.scp`, and `bolyra.nonce` are
   present and are valid hex strings.

## 5.3. Expiration Policy

Session tokens MUST have a maximum lifetime of 900 seconds (15
minutes). Issuers SHOULD default to 300 seconds (5 minutes). Tokens
with `exp - iat > 900` MUST be rejected.

Relying parties requiring longer sessions SHOULD implement token
refresh by re-running the handshake, not by extending token lifetime.

# 6. Security Considerations

## 6.1. Replay Attacks

The combination of `jti` (unique token ID) and `bolyra.nonce`
(handshake-bound nonce) provides two layers of replay protection.
Relying parties MUST track consumed `jti` values for the token's
validity window.

## 6.2. Nullifier Linkability

The `sub` (humanNullifier) and `bolyra.agn` (agentNullifier) claims
are deterministic outputs of the ZKP circuits. Any party that observes
multiple tokens with the same `sub` can link them to the same human
identity holder. Issuers and relying parties SHOULD treat these values
as pseudonymous identifiers and apply appropriate data handling
policies.

## 6.3. vtx Staleness

The `vtx` header points to a specific on-chain transaction. Chain
reorganizations may invalidate the referenced transaction. Relying
parties that audit `vtx` values SHOULD wait for sufficient block
confirmations before treating the reference as final.

## 6.4. Key Management

Issuers MUST protect signing keys with appropriate HSM or key
management practices. Compromise of the issuer's signing key allows
forging arbitrary session tokens.

## 6.5. Clock Skew

Relying parties SHOULD allow a clock skew tolerance of no more than
30 seconds when validating `iat` and `exp`.

# 7. IANA Considerations

## 7.1. Media Type Registration

Type name: application
Subtype name: bolyra+jwt
Required parameters: none
Optional parameters: none
Encoding considerations: binary (JWT compact serialization)
Security considerations: See Section 6 of this document

## 7.2. JWT Claims Registration

The following claims are registered in the IANA "JSON Web Token Claims"
registry:

- `bolyra.agn`: Agent nullifier hash
- `bolyra.scp`: Scope commitment hash
- `bolyra.nonce`: Session nonce (handshake-bound)
- `bolyra.vtx`: Verification transaction hash
- `bolyra.perm`: Permission bitmask

## 7.3. JOSE Header Parameter Registration

- `vtx`: Verification transaction hash (see Section 3.2)

# 8. References

## 8.1. Normative References

- [RFC7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- [RFC7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, May 2015.
- [RFC7517] Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.
- [RFC9449] Fett, D., Campbell, B., Bradley, J., Lodderstedt, T., Jones, M., and D. Waite, "OAuth 2.0 Demonstrating Proof of Possession (DPoP)", RFC 9449, September 2023.

## 8.2. Informative References

- [BOLYRA-AUTH] Swaminathan, V., "Mutual ZKP Authentication for Human-Agent Handshakes", draft-bolyra-mutual-zkp-auth-01, 2026.

# Appendix A. Example Token

## A.1. Header

```json
{
  "alg": "EdDSA",
  "typ": "bolyra+jwt",
  "vtx": "0x1234abcd5678ef901234abcd5678ef901234abcd5678ef901234abcd5678ef90"
}
```

## A.2. Payload

```json
{
  "sub": "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
  "iss": "https://verify.bolyra.ai",
  "iat": 1750000000,
  "exp": 1750000300,
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "bolyra.agn": "0x5566778899aabbcc5566778899aabbcc5566778899aabbcc5566778899aabbcc",
  "bolyra.scp": "0x1122334455667788112233445566778811223344556677881122334455667788",
  "bolyra.nonce": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "bolyra.perm": 7
}
```

# Appendix B. Comparison with Plain JWT

| Feature | Plain JWT | bolyra+jwt |
|---------|-----------|------------|
| Media type | `JWT` | `bolyra+jwt` |
| Replay protection | `jti` only | `jti` + `bolyra.nonce` (ZKP-bound) |
| On-chain audit trail | N/A | `vtx` header |
| Scope enforcement | Application-defined | `bolyra.scp` (circuit-enforced) |
| Nullifier binding | N/A | `sub` + `bolyra.agn` (deterministic) |
