# Section 7: Off-Chain Session Token Profile

**Normative addition to:** draft-bolyra-mutual-zkp-auth-01
**Status:** Experimental
**Date:** 2026-06-20
**References:** RFC 7519 (JWT), RFC 7518 (JWA), RFC 8725 (JWT Best Practices)

## 7.1 Introduction

After a successful on-chain `verifyHandshake()`, the relayer holds four public
signals: `nullifierHash`, `scopeCommitment`, `sessionNonce`, and the registry
contract address. Re-verifying the ZKP on every subsequent API call is
prohibitively expensive (~200ms per on-chain read). This section defines a JWT
profile (RFC 7519) that encodes verified handshake results into a short-lived
bearer token signed by the relayer, reducing per-call overhead to a single
ECDSA signature check (~0.5ms).

## 7.2 JOSE Header

The protected header MUST contain:

```
alg                = "ES256"
typ                = "JWT"
x-bolyra-registry  = checksummed-eth-address
x-bolyra-chain-id  = EIP-155-chain-id
```

| Field | Type | Required | Description |
|---|---|---|---|
| `alg` | string | REQUIRED | MUST be `ES256` (ECDSA over P-256, SHA-256). |
| `typ` | string | REQUIRED | MUST be `JWT`. |
| `x-bolyra-registry` | string | REQUIRED | EIP-55 checksummed address of the on-chain Bolyra registry contract. |
| `x-bolyra-chain-id` | number | REQUIRED | EIP-155 chain ID of the network where the registry is deployed. |

- `ES256` is chosen for broad HSM and WebCrypto compatibility.
- `x-bolyra-registry` links the off-chain token to the on-chain source of truth.
- `x-bolyra-chain-id` prevents cross-chain replay.
- Implementations MUST reject tokens with any `alg` other than `ES256`.

## 7.3 JWT Payload Claims

### 7.3.1 Claim Namespace

| Claim | JWT Name | Type | Required | Description |
|---|---|---|---|---|
| Issuer | `iss` | string | REQUIRED | Registry contract address (same as `x-bolyra-registry`). |
| Subject | `sub` | string | REQUIRED | `nullifierHash` from the HumanUniqueness circuit (hex32). |
| Scope | `scope` | string | REQUIRED | `scopeCommitment` encoded as base64url. |
| Nonce | `nonce` | string | REQUIRED | `sessionNonce` from the handshake (hex32). |
| Expiration | `exp` | NumericDate | REQUIRED | Token expiration (Unix seconds). |
| Issued At | `iat` | NumericDate | REQUIRED | Token issuance time (Unix seconds). |
| JWT ID | `jti` | string | REQUIRED | UUID v4 for replay prevention. |
| Root | `bolyra_root` | string | REQUIRED | `humanMerkleRoot` from the proof (hex32). |

### 7.3.2 Hex32 Format

All `hex32` values MUST be lowercase, `0x`-prefixed, zero-padded to exactly
66 characters (`"0x"` + 64 hex digits).

### 7.3.3 Scope Encoding

The `scope` claim carries the `scopeCommitment` (a 32-byte Poseidon hash)
encoded as base64url per RFC 4648 Section 5. This encoding was chosen over
raw hex to align with OAuth 2.0 scope semantics while remaining compact.

## 7.4 Signing Key Lifecycle

1. The relayer generates a `secp256r1` (P-256) key pair.
2. The compressed public key is published to the registry via `setRelayerKey(bytes)`.
3. Consumers fetch the active key from the registry or a cached JWKS endpoint.
4. On compromise, the relayer calls `rotateRelayerKey(bytes newKey)`.
5. A **grace period** of 300 seconds (5 minutes) MUST be observed during
   rotation: tokens signed with the old key remain valid until their `exp`.
6. Relayers SHOULD rotate keys at least every 30 days.

## 7.5 Token TTL Policy

| Parameter | Value |
|---|---|
| Default TTL | 900 seconds (15 minutes) |
| Minimum TTL | 60 seconds |
| Maximum TTL | 3600 seconds (1 hour) |

- `exp` MUST equal `iat + ttl` where `60 <= ttl <= 3600`.
- `exp` MUST NOT exceed the on-chain session expiry: `handshakeBlockTimestamp + maxSessionTTL`.
- Verifiers MUST reject tokens where `exp - iat > 3600`.
- Verifiers MUST reject tokens where `iat` is more than 60 seconds in the future
  (clock skew tolerance).

## 7.6 Revocation Model

**MVP: Stateless (short TTL).** The primary revocation mechanism is the short
token lifetime. Tokens are not stored server-side; expiration is the sole
invalidation signal.

**Future extension: `jti`-based blocklist.** The `jti` claim enables a
future revocation model where relayers maintain an in-memory set of revoked
JWT IDs. This set need only cover the maximum TTL window (3600 seconds).

**Tradeoff:** Stateless revocation accepts that a compromised token remains
valid until `exp`. For most API gateway use cases, the 15-minute default TTL
limits the blast radius. Applications requiring instant revocation SHOULD
implement the `jti` blocklist extension and reduce TTL to 60 seconds.

## 7.7 Validation Rules

1. Verify the ES256 signature against the relayer's public key.
2. Check `exp > now` (with 60-second clock skew tolerance).
3. Check `iat <= now + 60` (reject future-dated tokens).
4. Check `exp - iat <= 3600` (TTL ceiling).
5. Check `iss` matches `x-bolyra-registry` in the header.
6. Check `x-bolyra-chain-id` matches the expected network.
7. Validate `sub` is a well-formed hex32 string.
8. Validate `nonce` is a well-formed hex32 string.
9. Validate `bolyra_root` is a well-formed hex32 string.
10. Optionally verify `jti` is not in the revocation blocklist.

## 7.8 Security Considerations

1. **Replay protection**: The `nonce` (sessionNonce) binds the token to a
   specific handshake. The `jti` provides per-token uniqueness.
2. **Cross-chain replay**: The `x-bolyra-chain-id` header prevents tokens
   minted on Base Sepolia from being accepted on mainnet.
3. **Registry binding**: The `iss` and `x-bolyra-registry` double-bind the
   token to a specific on-chain contract, preventing registry spoofing.
4. **Key rotation**: The 300-second grace period ensures in-flight tokens
   survive a key rotation without requiring distributed key coordination.
5. **Token leakage**: Tokens MUST be transmitted only over TLS 1.2+.
   Tokens SHOULD NOT be logged or persisted to disk.

## 7.9 Example Token

```json
{
  "header": {
    "alg": "ES256",
    "typ": "JWT",
    "x-bolyra-registry": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    "x-bolyra-chain-id": 84532
  },
  "payload": {
    "iss": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    "sub": "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
    "scope": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_",
    "nonce": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "exp": 1750407300,
    "iat": 1750406400,
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "bolyra_root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }
}
```
