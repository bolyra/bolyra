# Bolyra Session Token JWT Profile

**Draft:** bolyra-session-token-jwt-01  
**Status:** Experimental  
**Date:** 2026-06-20  
**Authors:** ZKProva Inc.  
**References:** RFC 7519 (JWT), RFC 7518 (JWA), RFC 8725 (JWT Best Practices)

## 1. Introduction

After a successful on-chain Bolyra handshake verification, the verifier holds four
public signals: `humanNullifier`, `agentNullifier`, `sessionNonce`, and
`scopeCommitment`. Querying on-chain state for every subsequent API call is
prohibitively expensive (~200ms per verification). This specification defines a
JWT profile that encodes these signals into a short-lived bearer token signed by
the relayer, reducing per-call overhead to a single ECDSA or EdDSA signature
check (~0.5ms).

## 2. Terminology

- **Relayer**: The off-chain service that calls the on-chain verifier contract
  and mints session tokens upon successful verification.
- **Handshake**: The mutual ZKP authentication between a human identity holder
  and an AI agent, verified on-chain.
- **Delegation chain**: An ordered sequence of nullifier hashes representing
  the path from root delegator to the current session holder.

## 3. JWT Header

The JOSE header MUST contain exactly:

```
alg = "ES256" / "EdDSA"
typ = "bolyra+jwt"
```

- `ES256` (ECDSA over P-256) is the default for browser and cloud HSM
  compatibility.
- `EdDSA` (Ed25519) is permitted for relayers using Ed25519 key material.
- Implementations MUST reject tokens with any other `alg` value.
- The `typ` field distinguishes Bolyra session tokens from generic JWTs.

## 4. JWT Payload Claims

### 4.1 ABNF

```abnf
bolyra-claims   = humanNullifier
                  agentNullifier
                  sessionNonce
                  scopeCommitment
                  delegationChain
                  chainId
                  verifierContract
                  iss
                  sub
                  iat
                  exp

humanNullifier   = hex32           ; HumanUniqueness circuit nullifier
agentNullifier   = hex32           ; AgentPolicy circuit nullifier
sessionNonce     = hex32           ; Fresh nonce binding proof to session
scopeCommitment  = hex32           ; Poseidon(permissions, salt)
delegationChain  = json-array      ; Ordered array of hex32 nullifiers
chainId          = pos-integer     ; EVM chain ID of verifier network
verifierContract = eth-address     ; 0x-prefixed, 40-char hex (EIP-55)

hex32            = "0x" 64HEXDIG  ; 32-byte value, lowercase hex
eth-address      = "0x" 40HEXDIG  ; 20-byte Ethereum address
pos-integer      = 1*DIGIT        ; Positive integer
json-array       = "[" *(hex32 ",") hex32 "]" / "[]"  ; JSON array

iss              = string          ; Relayer identifier (URI or DID)
sub              = hex32           ; MUST equal humanNullifier
iat              = NumericDate     ; RFC 7519 Section 2
exp              = NumericDate     ; RFC 7519 Section 2
```

### 4.2 Claim Definitions

| Claim | Type | Required | Description |
|---|---|---|---|
| `humanNullifier` | `hex32` | REQUIRED | Nullifier hash from the HumanUniqueness circuit. |
| `agentNullifier` | `hex32` | REQUIRED | Nullifier hash from the AgentPolicy circuit. |
| `sessionNonce` | `hex32` | REQUIRED | Fresh nonce binding handshake to this session. |
| `scopeCommitment` | `hex32` | REQUIRED | Poseidon hash of (permissions, salt) committed on-chain. |
| `delegationChain` | `hex32[]` | REQUIRED | Ordered JSON array of nullifier hex strings, root to leaf. Empty array `[]` for non-delegated sessions. |
| `chainId` | `number` | REQUIRED | EVM chain ID where the verifier contract is deployed. |
| `verifierContract` | `eth-address` | REQUIRED | Address of the on-chain verifier contract. |
| `iss` | `string` | REQUIRED | Relayer identifier. SHOULD be a `did:bolyra:` DID or HTTPS URI. |
| `sub` | `hex32` | REQUIRED | MUST equal `humanNullifier`. Enables standard JWT tooling to extract the subject. |
| `iat` | `NumericDate` | REQUIRED | Issued-at Unix timestamp (seconds). |
| `exp` | `NumericDate` | REQUIRED | Expiration Unix timestamp (seconds). |

All `hex32` values MUST be lowercase, `0x`-prefixed, zero-padded to exactly
66 characters ("0x" + 64 hex digits).

### 4.3 Delegation Chain Encoding

`delegationChain` is a JSON array of `hex32` nullifier strings ordered from
root delegator to leaf (current session holder):

```json
"delegationChain": [
  "0xaaaa...1111",
  "0xbbbb...2222",
  "0xcccc...3333"
]
```

- For non-delegated sessions, the array MUST be empty: `[]`.
- Each entry represents a delegation hop verified by the Delegation circuit.
- Verifiers SHOULD validate that the chain length does not exceed their
  configured maximum depth.

## 5. TTL Policy

| Parameter | Value |
|---|---|
| Default TTL | 300 seconds (5 minutes) |
| Minimum TTL | 30 seconds |
| Maximum TTL | 3600 seconds (1 hour) |

- `exp` MUST equal `iat + ttl` where `30 <= ttl <= 3600`.
- Relayers MUST reject tokens where `exp - iat > 3600`.
- Relayers MUST reject tokens where `iat` is more than 60 seconds in the future
  (clock skew tolerance).
- Consumers SHOULD treat tokens with less than 30 seconds remaining as
  effectively expired and request re-authentication.

## 6. Claim Validation Rules

### 6.1 Signature Verification

The token MUST be verified against the relayer's public key using the algorithm
specified in the header. Only `ES256` and `EdDSA` are permitted.

### 6.2 Scope Commitment

`scopeCommitment` MUST equal `Poseidon(permissions, salt)` as committed in the
on-chain verifier. Verifiers that enforce scope SHOULD recompute the Poseidon
hash from known inputs and compare.

### 6.3 Chain ID Binding

`chainId` MUST match the EVM network where `verifierContract` is deployed.
A token minted on Base Sepolia (chain ID 84532) MUST NOT be accepted by a
verifier expecting Ethereum mainnet (chain ID 1).

### 6.4 Subject Binding

`sub` MUST equal `humanNullifier`. Implementations MUST reject tokens where
these values differ.

### 6.5 Issuer Validation

Consumers MUST maintain an allowlist of trusted issuers and reject tokens from
unknown issuers.

## 7. Security Considerations

1. **Replay protection**: The `sessionNonce` binds the token to a specific
   handshake session. Services SHOULD track seen nonces within the token's
   TTL window.
2. **Key rotation**: Relayers SHOULD support JWK Set endpoints for key
   rotation. Consumers SHOULD cache keys with a TTL no longer than 1 hour.
3. **Token leakage**: Tokens MUST be transmitted only over TLS 1.2+.
   Tokens SHOULD NOT be logged or persisted.
4. **Clock skew**: The 60-second future `iat` tolerance balances distributed
   system clock drift against replay risk.
5. **Delegation depth**: Unbounded delegation chains increase verification
   cost. Implementations SHOULD enforce a maximum depth (recommended: 5).

## 8. Examples

### 8.1 Minimal Token (No Delegation)

```json
{
  "header": {
    "alg": "ES256",
    "typ": "bolyra+jwt"
  },
  "payload": {
    "humanNullifier": "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
    "agentNullifier": "0x1122334455667788112233445566778811223344556677881122334455667788",
    "sessionNonce": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "scopeCommitment": "0x00000000000000000000000000000000000000000000000000000000000000ff",
    "delegationChain": [],
    "chainId": 84532,
    "verifierContract": "0x1234567890abcdef1234567890abcdef12345678",
    "iss": "did:bolyra:relayer:base-sepolia",
    "sub": "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
    "iat": 1750406400,
    "exp": 1750406700
  }
}
```

### 8.2 Token with 3-Hop Delegation Chain

```json
{
  "payload": {
    "delegationChain": [
      "0x1111111111111111111111111111111111111111111111111111111111111111",
      "0x2222222222222222222222222222222222222222222222222222222222222222",
      "0x3333333333333333333333333333333333333333333333333333333333333333"
    ]
  }
}
```

## 9. IANA Considerations

This document registers the `bolyra+jwt` media type subtype for use in the
JOSE `typ` header parameter.
