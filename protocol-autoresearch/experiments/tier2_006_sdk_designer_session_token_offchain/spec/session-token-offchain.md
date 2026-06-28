# SD-JWT Session Tokens for Off-Chain Proof Reuse

**Status:** Draft  
**Version:** 0.1.0  
**Authors:** Bolyra Protocol Team  
**SPDX-License-Identifier:** Apache-2.0

## Abstract

This specification defines an SD-JWT (Selective Disclosure JWT) session token format for the Bolyra protocol. After a successful `verifyHandshake()`, the verifier mints a short-lived token that binds the verified proof outputs. Subsequent API calls present this token instead of generating a fresh ZK proof (which takes 1-5 seconds), reducing per-call latency to a simple HMAC verification.

## Motivation

Every Bolyra handshake requires generating and verifying a ZK proof — the most expensive operation in the protocol. For session-oriented interactions (e.g., an AI agent making multiple API calls within a conversation), re-proving on every call is prohibitively expensive. Session tokens bridge the gap between the strong initial proof and lightweight ongoing authentication.

## Claim Set

| Claim | Type | SD | Description |
|---|---|---|---|
| `nullifierHash` | string (hex) | Yes | Human nullifier hash from HumanUniqueness proof |
| `scopeCommitment` | string (hex) | Yes | Scope commitment binding from handshake |
| `agentId` | string (hex) | Yes | Agent credential hash or agent nullifier |
| `humanMerkleRoot` | string (hex) | Yes | Human Merkle tree root at proof time |
| `iss` | string | No | Issuer identifier (default: `bolyra.ai`) |
| `aud` | string | No | Audience (optional, verifier-specific) |
| `iat` | number | No | Issued-at (Unix seconds) |
| `exp` | number | No | Expiry (Unix seconds) |
| `_sd_alg` | string | No | Hash algorithm for SD digests (`sha-256`) |
| `_sd` | string[] | No | Array of disclosure digests |

### Selective Disclosure

All four core claims (`nullifierHash`, `scopeCommitment`, `agentId`, `humanMerkleRoot`) support selective disclosure per [SD-JWT draft-ietf-oauth-selective-disclosure-jwt-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/). Each disclosure is a base64url-encoded JSON array `[salt, claimName, claimValue]`. The JWT payload contains only the SHA-256 digest of each disclosure in the `_sd` array.

This allows presenters to reveal only the claims required by each verifier. For example, a rate-limiting endpoint may only need `nullifierHash`, while a financial endpoint may require `scopeCommitment` and `agentId`.

## TTL Policy

| Parameter | Value | Rationale |
|---|---|---|
| Default TTL | 300s (5 min) | Covers a typical API session |
| Minimum TTL | 60s | Below this, re-proving is more efficient |
| Maximum TTL | 3600s (1 hour) | Bounds token theft exposure window |

### Recommended TTL by Threat Level

| Threat Level | TTL | Use Case |
|---|---|---|
| High (financial) | 60-120s | Payment APIs, PII access |
| Medium (write) | 300s | Data mutation endpoints |
| Low (read-only) | 600-3600s | Read-only APIs, public data |

## Replay Prevention

Session tokens are **not** replay-proof by themselves. Replay prevention relies on two mechanisms:

1. **nullifierHash binding**: The `nullifierHash` is single-use at ZK proof time. The on-chain `IdentityRegistry` records spent nullifiers, preventing the same human from re-proving with the same external nullifier. The session token inherits this uniqueness.

2. **Short TTL**: The token expires quickly, bounding the window during which a stolen token could be replayed. Combined with TLS (preventing network-layer theft), the exposure is minimal.

For high-security contexts, verifiers SHOULD additionally bind tokens to a transport-layer property (e.g., TLS channel binding via `tls-exporter` or client IP).

## Token Format

Compact SD-JWT serialization:

```
<header>.<payload>.<signature>~<disclosure1>~<disclosure2>~...~
```

- **Header**: `{ "alg": "HS256", "typ": "sd+jwt" }`
- **Payload**: Contains `iss`, `iat`, `exp`, `_sd_alg`, `_sd`, and optionally `aud`
- **Signature**: HMAC-SHA256 over `header.payload`
- **Disclosures**: Tilde-separated base64url-encoded `[salt, name, value]` arrays

## Security Considerations

### Token Theft

A stolen session token grants the bearer all disclosed claims until expiry. Mitigations:
- Keep TTL short (default 300s)
- Use TLS for all token transport
- Consider binding to client IP or TLS channel for high-value operations
- Rotate signing keys periodically

### Clock Skew

Verifiers SHOULD allow a configurable clock skew tolerance (default: 30s) to handle minor clock drift between issuer and verifier. The tolerance applies only to the `exp` check — tokens issued in the future (`iat > now`) are always rejected.

### Signing Key Management

The HMAC-SHA256 shared secret MUST be:
- At least 256 bits (32 bytes)
- Generated from a cryptographically secure random source
- Stored securely (not in source code or environment variables in plaintext)
- Rotated when compromised or per organizational policy

### Disclosure Privacy

Selective disclosure prevents over-sharing, but verifiers can still collude to reconstruct the full claim set. For privacy-critical deployments, use different `nullifierHash` external nullifiers per verifier (already supported by the HumanUniqueness circuit's external nullifier parameter).
