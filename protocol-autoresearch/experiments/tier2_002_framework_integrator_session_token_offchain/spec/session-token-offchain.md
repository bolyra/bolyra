# Off-Chain Session Token Specification

**Status:** Draft  
**Version:** 0.1.0  
**Authors:** Bolyra Protocol Team  
**Date:** 2026-06-19

## 1. Motivation

LangChain/CrewAI agent chains make 10–50 tool calls per task. Requiring an on-chain
`verifyHandshake()` per call is prohibitively slow (~2s per tx) and expensive (~$0.02–0.10
per verification on L2). Session tokens amortize a single on-chain verification across
many off-chain tool calls.

## 2. Session Token Payload (JWT)

The session token is a signed JWT (RFC 7519) with the following payload schema:

```json
{
  "proofDigest": "<hex string: SHA-256 of humanProof || agentProof bytes>",
  "humanNullifier": "<hex string: nullifier hash from HumanUniqueness proof>",
  "agentCredHash": "<hex string: Poseidon hash of agent credential>",
  "scopeBitmap": 255,
  "sessionNonce": "<hex string: 32-byte cryptographically random value>",
  "iat": 1719000000,
  "exp": 1719003600,
  "iss": "bolyra.ai"
}
```

### Field Definitions

| Field | Type | Description |
|---|---|---|
| `proofDigest` | `string` (hex) | SHA-256 hash of concatenated `humanProof` and `agentProof` byte arrays. Binds the session to a specific verified handshake. |
| `humanNullifier` | `string` (hex) | The `nullifierHash` public output from the HumanUniqueness circuit. Identifies the human without revealing identity. |
| `agentCredHash` | `string` (hex) | Hash of the agent credential used in the handshake. |
| `scopeBitmap` | `number` (0–255) | 8-bit cumulative permission bitmap. Must be a subset of the handshake's verified scope. Must satisfy cumulative-bit implication rules. |
| `sessionNonce` | `string` (hex) | 32-byte random value generated at mint time. Used for replay prevention and revocation. |
| `iat` | `number` | Issued-at timestamp (Unix seconds). |
| `exp` | `number` | Expiry timestamp (Unix seconds). Default: `iat + 3600`. |
| `iss` | `string` | Always `"bolyra.ai"`. |

## 3. Signing Key Lifecycle

- An ephemeral ECDSA P-256 key pair is generated **per SDK instance** (per process).
- The private key **never leaves process memory** — it is not serialized, persisted, or transmitted.
- The public key is used for in-process verification only.
- When the process terminates, all session tokens become unverifiable (fail-safe).
- Key rotation: instantiate a new SDK session manager to rotate keys.

## 4. Off-Chain Verification Algorithm

```
verifySessionToken(token, requiredScope?):
  1. Decode JWT header and payload (without verification).
  2. Verify JWT signature against in-process public key.
     → If invalid: throw BolyraSessionError('INVALID_SIGNATURE')
  3. Check exp > currentTime.
     → If expired: throw BolyraSessionError('TOKEN_EXPIRED')
  4. Check iss === 'bolyra.ai'.
     → If mismatch: throw BolyraSessionError('INVALID_ISSUER')
  5. If requiredScope provided:
     Check (payload.scopeBitmap & requiredScope) === requiredScope.
     → If insufficient: throw BolyraSessionError('INSUFFICIENT_SCOPE')
  6. Check sessionNonce is NOT in the revocation set.
     → If revoked: throw BolyraSessionError('TOKEN_REVOKED')
  7. Return decoded payload.
```

## 5. Replay Prevention

Replay prevention is handled via the `sessionNonce`:

- Each minted session token contains a unique 32-byte `sessionNonce`.
- The nonce is included in the signed JWT payload, so it cannot be forged.
- `revokeSessionToken()` adds the nonce to an in-process `Set<string>`.
- All subsequent `verifySessionToken()` calls check this set.

**Important:** The revocation set is **process-local**. For distributed deployments,
applications must either:
- Use short expiry times (recommended: 300–3600 seconds), or
- Propagate the revocation set via application-layer mechanisms (Redis, DB, etc.).

## 6. Checkpoint Anchoring

Periodic on-chain anchoring provides a tamper-evident audit trail:

1. Collect all active session nonces: `nonces = activeSessions.map(s => s.sessionNonce)`.
2. Sort nonces lexicographically.
3. Compute `sessionRoot = keccak256(abi.encodePacked(sortedNonces))`.
4. Call `BolyraSessionAnchor.batchCheckpoint(sessionRoot, currentEpoch)` on-chain.

### Recommended Cadence

- Every 10 tool calls, or
- Every 60 seconds, whichever comes first.
- Never per-call (defeats the purpose of off-chain sessions).

## 7. Revocation Surface

| Method | Scope | Latency |
|---|---|---|
| `revokeSessionToken(token)` | Process-local | Immediate |
| Short expiry (5 min) | Global | Up to 5 min |
| Application-layer broadcast | Distributed | Application-dependent |
| On-chain checkpoint gap | Audit trail | Next checkpoint epoch |

## 8. Security Considerations

- **No ZK verification in session flow:** The session token trusts the initial `verifyHandshake()` result. If the on-chain verification is compromised, session tokens inherit that compromise.
- **Scope narrowing only:** `mintSessionToken()` can narrow scope (remove bits) but never widen. Enforced by `validateCumulativeBitEncoding()` and bitwise subset check.
- **Process boundary:** Session tokens are meaningless outside the originating process. This is a feature, not a bug — it limits blast radius.
- **Clock skew:** Verifiers should allow a small clock skew tolerance (recommended: 30 seconds) for `exp` checks in distributed settings. The reference implementation does not add skew tolerance.
