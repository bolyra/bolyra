# Bolyra Session Token Schema

*JWT profile for off-chain session tokens after on-chain handshake verification.*

## 1. Overview

After a successful mutual ZKP handshake (`verifyHandshake()`), the verifier
MAY issue a short-lived JWT to amortize verification cost across subsequent
calls within the same session. The session token is a JSON Web Token
[RFC 7519] signed with ES256 (P-256 ECDSA) [RFC 7518 §3.4].

## 2. JWT Header

```json
{
  "alg": "ES256",
  "typ": "JWT"
}
```

Implementations MUST reject tokens with any algorithm other than `ES256`
to prevent algorithm confusion attacks.

## 3. JWT Payload Claims

| Claim | Required | Type | Description |
|-------|----------|------|-------------|
| `sub` | MUST | `string` | The `nullifierHash` from the human uniqueness proof (hex-encoded, 0x-prefixed). Uniquely identifies the human within the session. |
| `scope` | MUST | `string` | The hex-encoded `scopeCommitment` — Poseidon commitment to the granted scope bitmap. |
| `exp` | MUST | `number` | Expiration timestamp (Unix seconds). |
| `iat` | MUST | `number` | Issued-at timestamp (Unix seconds). |
| `iss` | MUST | `string` | Issuer identifier. Always `"bolyra"`. |
| `aud` | SHOULD | `string \| string[]` | Audience: `"langchain"`, `"crewai"`, `"*"` (wildcard). Default: `"*"`. |

## 4. Signing Key Requirements

- **Algorithm:** ES256 (ECDSA with P-256 curve and SHA-256)
- **Key type:** `CryptoKey` from the Web Crypto API (`SubtleCrypto`)
- **Key generation:**
  ```typescript
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // non-extractable in production
    ['sign', 'verify'],
  );
  ```
- Alternatively, use `jose.generateKeyPair('ES256')` which wraps the above.

## 5. Recommended TTLs

| Use Case | TTL | Rationale |
|----------|-----|-----------|
| Agent multi-tool chain | 3600s (1 hour) | Covers a full task execution (10–200 calls). |
| High-security financial | 300s (5 min) | Limits exposure for financial operations. |
| Interactive session | 1800s (30 min) | Balances UX and security for human-supervised flows. |

Default: **3600 seconds (1 hour)**.

## 6. Replay Prevention

Replay prevention relies on **nullifier uniqueness**:

1. The `sub` claim contains the `nullifierHash`, which is unique per
   (identity, scope, epoch) tuple.
2. Verifiers SHOULD maintain a set of seen nullifiers for the current epoch.
3. A replayed token with an already-consumed nullifier MUST be rejected
   at the application layer.
4. The on-chain nullifier registry (`BolyraRegistry.isNullifierUsed()`)
   remains the ground truth; the JWT is a **session cache** that defers
   to on-chain state when the token expires or on suspicious activity.

## 7. Verification Algorithm

To verify a session token, the relying party MUST:

1. Parse the JWT and extract the protected header.
2. Confirm `alg` is `ES256`. Reject all other algorithms.
3. Verify the ECDSA signature using the verifier's P-256 public key.
4. Check that `exp > current_time`. Reject expired tokens.
5. Optionally check `aud` matches the expected framework identifier.
6. Extract `sub` (nullifier) and `scope` for authorization decisions.

## 8. Security Considerations

- **Bearer token risk**: Session tokens are bearer credentials. They MUST
  be transmitted over TLS and stored only in memory (never persisted).
- **Key rotation**: Verifiers SHOULD rotate their P-256 signing keys
  periodically and MUST rotate immediately on suspected compromise.
- **Algorithm confusion**: Implementations MUST NOT accept tokens with
  `alg` values other than `ES256` to prevent downgrade attacks.
- **Token ≠ proof**: The JWT does not replace the ZK proof. It is a
  performance optimization. Security-critical operations SHOULD
  re-verify the original proof on-chain.
- **Clock skew**: Implementations SHOULD allow a small clock skew
  tolerance (e.g., 5 seconds) when checking `exp` and `iat` claims.
