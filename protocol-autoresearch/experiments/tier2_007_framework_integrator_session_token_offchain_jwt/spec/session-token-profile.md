# Section 7: Session Token Profile

*Appendix to `draft-bolyra-mutual-zkp-auth-01`*

## 7.1 Overview

After a successful mutual ZKP handshake (Section 4), the verifier MAY issue
a short-lived session token to amortize verification cost across subsequent
calls within the same session. The session token is a JSON Web Token (JWT)
[RFC 7519] signed with EdDSA [RFC 8037] using an Ed25519 key pair controlled
by the verifier.

## 7.2 JWT Header

```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

The `alg` value MUST be `EdDSA`. Implementations MUST reject tokens with
any other algorithm to prevent algorithm confusion attacks.

## 7.3 JWT Claims

| Claim | Required | Type | Description |
|-------|----------|------|-------------|
| `nullifierHash` | MUST | string | The nullifier hash from the human uniqueness proof (hex-encoded). |
| `scopeCommitment` | MUST | string | The Poseidon commitment to the scope bitmap (hex-encoded). |
| `sessionNonce` | MUST | string | The nonce used in the handshake. MUST match the `sessionNonce` from the `verifyHandshake()` call (hex-encoded). |
| `iat` | MUST | number | Issued-at timestamp (Unix seconds). |
| `exp` | MUST | number | Expiration timestamp (Unix seconds). |
| `iss` | SHOULD | string | Issuer identifier. Default: `"bolyra.ai"`. |

## 7.4 TTL Limits

- **Minimum TTL**: 60 seconds. Tokens with `exp - iat < 60` MUST be rejected
  by conformant verifiers.
- **Maximum TTL**: 900 seconds (15 minutes). Tokens with `exp - iat > 900`
  MUST be rejected.
- **Recommended default**: 300 seconds (5 minutes).

Rationale: Short TTLs limit the window of exposure from a stolen bearer token.
The 5-minute default covers a typical agentic multi-tool chain (10–50 calls)
without requiring re-verification.

## 7.5 Nonce Binding Requirement

The `sessionNonce` claim MUST be identical to the `sessionNonce` used during
the on-chain `verifyHandshake()` call that authorized this session. Verifiers
MUST reject tokens whose `sessionNonce` does not match the expected value for
the session context.

This binding prevents an attacker from replaying a session token minted for
one handshake against a different handshake context.

## 7.6 Verification Algorithm

To verify a session token, the relying party MUST:

1. Parse the JWT and extract the header.
2. Confirm `alg` is `EdDSA`. Reject all other algorithms.
3. Verify the signature using the verifier's Ed25519 public key.
4. Check that `exp > current_time`. Reject expired tokens.
5. Check that `exp - iat` is within [60, 900]. Reject out-of-range TTLs.
6. Confirm `sessionNonce` matches the expected handshake nonce.
7. Extract `nullifierHash` and `scopeCommitment` for authorization decisions.

## 7.7 Revocation

Session tokens are short-lived by design and do not require a dedicated
revocation mechanism in the common case. However, implementations MAY
maintain a process-local set of revoked nonces for immediate invalidation.

Distributed revocation (e.g., via a shared cache or on-chain checkpoint) is
an application-layer concern and is out of scope for this specification.

## 7.8 Security Considerations

- **Bearer token risk**: Session tokens are bearer credentials. They MUST be
  transmitted over TLS and stored only in memory (never persisted to disk).
- **Key rotation**: Verifiers SHOULD rotate their Ed25519 signing keys
  periodically and MUST rotate immediately on suspected compromise.
- **Algorithm confusion**: Implementations MUST NOT accept tokens with
  `alg` values other than `EdDSA` to prevent downgrade attacks.
- **Clock skew**: Implementations SHOULD allow a small clock skew tolerance
  (e.g., 5 seconds) when checking `exp` and `iat` claims.
