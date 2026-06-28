# Bolyra Session Token Claims Registry

Normative claims registry for the `bolyra+jwt` session token profile
defined in `draft-bolyra-session-token-01`.

## 1. Registered JWT Claims (RFC 7519)

| JWT Claim | Handshake Output | Type | Description | Required |
|-----------|-----------------|------|-------------|----------|
| `sub` | `humanNullifier` | string (hex) | Poseidon hash nullifier derived from the human's identity secret and external nullifier. Uniquely identifies the human within a given scope without revealing the identity commitment. | REQUIRED |
| `iss` | (verifier identity) | string (URI) | The URI or DID of the entity that verified the handshake proofs on-chain and signed this token. | REQUIRED |
| `iat` | `verificationTimestamp` | number (Unix epoch) | The time at which the on-chain verification transaction was confirmed. | REQUIRED |
| `exp` | `iat + ttl` | number (Unix epoch) | Token expiration. MUST satisfy `exp - iat <= 900`. Default: `iat + 300`. | REQUIRED |
| `jti` | (generated) | string (UUID v4) | Unique token identifier for replay detection. Generated at issuance time. | REQUIRED |

## 2. Private Claims (bolyra.* namespace)

| JWT Claim | Handshake Output | Type | Description | Required |
|-----------|-----------------|------|-------------|----------|
| `bolyra.agn` | `agentNullifier` | string (hex) | Nullifier hash derived from the agent's EdDSA-signed credential. Uniquely identifies the agent credential without revealing the signing key. | REQUIRED |
| `bolyra.scp` | `scopeCommitment` | string (hex) | Poseidon hash commitment to the delegated permission scope. Binds the token to a specific set of permissions enforced by the Delegation circuit. | REQUIRED |
| `bolyra.nonce` | `sessionNonce` | string (hex) | The nonce committed into both the HumanUniqueness and AgentPolicy proofs. Provides cryptographic binding between the ZKP handshake and this token. Must be unique per session. | REQUIRED |
| `bolyra.vtx` | (on-chain tx hash) | string (hex) | The transaction hash of the on-chain verification call. Redundant with the JOSE header `vtx` parameter; included in payload for claim-level programmatic access. | OPTIONAL |
| `bolyra.perm` | `permissions` | number (0-255) | 8-bit cumulative permission bitmask. Higher bits imply lower bits per Bolyra permission model. | OPTIONAL |

## 3. JOSE Header Parameters

| Parameter | Source | Type | Description | Required |
|-----------|--------|------|-------------|----------|
| `alg` | (issuer choice) | string | `EdDSA` (RECOMMENDED) or `ES256`. | REQUIRED |
| `typ` | (fixed) | string | MUST be `bolyra+jwt`. | REQUIRED |
| `vtx` | (on-chain tx hash) | string (hex) | Transaction hash of the on-chain verification. `0x`-prefixed for EVM chains. | OPTIONAL |

## 4. Encoding Rules

- All hex-encoded values MUST use lowercase hex with `0x` prefix.
- `sub`, `bolyra.agn`, `bolyra.scp`, and `bolyra.nonce` MUST be
  64 hex characters (32 bytes) after the `0x` prefix.
- `bolyra.vtx` and header `vtx` MUST be 64 hex characters (32 bytes)
  after the `0x` prefix for EVM chains.
- `bolyra.perm` MUST be an integer in the range [0, 255].

## 5. Validation Rules

1. All REQUIRED claims MUST be present; absence is a validation error.
2. `exp - iat` MUST NOT exceed 900 seconds.
3. `bolyra.nonce` MUST be checked against a replay store.
4. `bolyra.perm`, if present, MUST satisfy cumulative bit encoding
   (bit 4 set implies bits 2 and 3 set; bit 3 set implies bit 2 set).
5. If both header `vtx` and claim `bolyra.vtx` are present, they MUST
   be identical.

## 6. DPoP Binding (RFC 9449)

When used in an OAuth 2.0 DPoP flow:

- The authorization server's DPoP `nonce` value is used as the
  `sessionNonce` input to `proveHandshake()`.
- The resulting `bolyra.nonce` in the session token is therefore
  cryptographically bound to the DPoP proof.
- Relying parties verifying the DPoP proof can cross-check
  `bolyra.nonce` against the DPoP `nonce` to confirm binding.
