# Bolyra Session Token Format

## `application/bolyra-session+jwt`

### Status

Draft — v0.1.0

### Abstract

This document defines the normative format for **Bolyra Session Tokens** (BST), a JWS Compact Serialization ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) token issued by a relying party after a successful on-chain Bolyra handshake verification. The token binds the handshake's public signals — `humanNullifier`, `agentNullifier`, `sessionNonce`, and `scopeCommitment` — into a short-lived bearer credential, allowing subsequent off-chain API calls without on-chain re-verification.

### 1. Introduction

A Bolyra mutual-ZKP handshake produces four public signals that attest to identity uniqueness (human), credential validity (agent), permission scope, and session freshness. On-chain verification is expensive; once verified, the relying party (RP) SHOULD mint a session token that downstream middleware can validate with a single signature check.

The BST is **not** a ZKP. The ZKP already happened on-chain. The BST is a signed attestation by the RP that the ZKP was valid at issuance time.

### 2. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### 3. Token Structure

A BST is a JWS Compact Serialization with three Base64url-encoded segments:

```
BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
```

#### 3.1 JOSE Header

The protected header MUST contain:

| Parameter | Value | Requirement |
|-----------|-------|-------------|
| `alg` | `ES256` or `EdDSA` | REQUIRED |
| `typ` | `bolyra-session+jwt` | REQUIRED |

Implementations MUST support `EdDSA` (Ed25519). Implementations SHOULD support `ES256` (P-256). Implementations MUST NOT use `HS256` or any symmetric algorithm.

ABNF:

```abnf
header = %x7B ; {
  '"alg"' ":" ( '"ES256"' / '"EdDSA"' ) ","
  '"typ"' ":" '"bolyra-session+jwt"'
  %x7D ; }
```

#### 3.2 Payload Claims

The JWT payload MUST contain the following claims:

| Claim | Type | Description | Requirement |
|-------|------|-------------|-------------|
| `humanNullifier` | `string` (bytes32 hex, `0x`-prefixed) | Nullifier hash from `HumanUniqueness` circuit | REQUIRED |
| `agentNullifier` | `string` (bytes32 hex, `0x`-prefixed) | Nullifier hash from `AgentPolicy` circuit | REQUIRED |
| `sessionNonce` | `string` (bytes32 hex, `0x`-prefixed) | Nonce binding the handshake to this session | REQUIRED |
| `scopeCommitment` | `string` (bytes32 hex, `0x`-prefixed) | Poseidon hash of the 8-bit cumulative permission encoding | REQUIRED |
| `iat` | `number` (NumericDate) | Issued-at timestamp (seconds since Unix epoch) | REQUIRED |
| `exp` | `number` (NumericDate) | Expiration timestamp | REQUIRED |
| `iss` | `string` (DID) | Issuer identifier, `did:bolyra:<verifier-id>` | REQUIRED |

All `bytes32 hex` values MUST be exactly 66 characters: `0x` followed by 64 lowercase hexadecimal digits.

ABNF for bytes32 hex:

```abnf
bytes32-hex = "0x" 64HEXDIG
HEXDIG      = DIGIT / %x61-66 ; 0-9 a-f (lowercase only)
```

#### 3.3 Signature

The signature MUST be computed over `ASCII(BASE64URL(header) "." BASE64URL(payload))` using the algorithm specified in the header.

The signing key MUST be an asymmetric key pair. Key discovery is via the `did:bolyra` DID Document's `verificationMethod` array, using the `assertionMethod` relationship. The key MUST be resolvable at the DID specified in the `iss` claim.

### 4. Validation Rules

A verifier MUST perform the following checks in order:

1. **Parse**: Decode the JWS Compact Serialization. If malformed, return `INVALID_SIGNATURE`.
2. **Algorithm**: Confirm `alg` is `ES256` or `EdDSA`. If not, return `INVALID_SIGNATURE`.
3. **Type**: Confirm `typ` is `bolyra-session+jwt`. If not, return `INVALID_SIGNATURE`.
4. **Signature**: Verify the JWS signature against the issuer's public key. If invalid, return `INVALID_SIGNATURE`.
5. **Expiry**: Confirm `exp > now`. If expired, return `EXPIRED_SESSION`.
6. **Nonce**: Confirm `sessionNonce` matches the expected session nonce. If mismatched, return `NONCE_MISMATCH`.
7. **Scope**: Decode the `scopeCommitment` and confirm the permission bits satisfy the required scope. If insufficient, return `SCOPE_INSUFFICIENT`.
8. **Claims format**: Confirm all required claims are present and correctly formatted bytes32 hex. If not, return `INVALID_SIGNATURE`.

### 5. Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `EXPIRED_SESSION` | 401 | Token `exp` is in the past |
| `NONCE_MISMATCH` | 401 | `sessionNonce` does not match expected value |
| `SCOPE_INSUFFICIENT` | 403 | Decoded permission bits do not satisfy required scope |
| `INVALID_SIGNATURE` | 401 | Signature verification failed, malformed token, or missing claims |

### 6. Session Lifetime Recommendations

| Scope Category | RECOMMENDED Max TTL |
|---------------|--------------------|
| `READ_DATA` only (bit 0) | 24 hours |
| `WRITE_DATA` (bit 1) | 4 hours |
| Financial scopes (bits 2–4) | 1 hour |
| `SIGN_ON_BEHALF` / `SUB_DELEGATE` (bits 5–6) | 15 minutes |
| `ACCESS_PII` (bit 7) | 1 hour |

Implementations SHOULD enforce a hard maximum of 86400 seconds (24 hours). Implementations MUST enforce a minimum TTL of 30 seconds.

### 7. Interoperability Requirements

- Tokens MUST be transmitted in the HTTP `Authorization` header as `Bearer <token>`.
- The `Content-Type` for endpoints that accept BSTs SHOULD be `application/bolyra-session+jwt`.
- Relying parties MUST NOT accept tokens with algorithms not listed in Section 3.1.
- Clock skew tolerance SHOULD be configurable, with a default of 0 seconds and a RECOMMENDED maximum of 60 seconds.

### 8. Security Considerations

- **Not a ZKP**: The BST is a signed attestation. It does not inherit ZKP privacy properties. The `humanNullifier` and `agentNullifier` are linkable within the session.
- **Replay protection**: The `sessionNonce` binding prevents cross-session replay. Relying parties SHOULD track issued nonces and reject duplicates.
- **Key compromise**: If the RP signing key is compromised, all outstanding BSTs become forgeable. Implementations SHOULD support key rotation via DID Document versioning.
- **Bearer token risks**: BSTs are bearer tokens. Transmission MUST occur over TLS 1.2+. Storage MUST use secure, HttpOnly cookies or equivalent platform-specific secure storage.

### 9. References

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) — JSON Web Signature (JWS)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT)
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) — Media Type Specifications and Registration Procedures
- [spec/did-method-bolyra.md](did-method-bolyra.md) — Bolyra DID Method
- [spec/draft-bolyra-mutual-zkp-auth-01.md](draft-bolyra-mutual-zkp-auth-01.md) — Bolyra Mutual ZKP Auth
