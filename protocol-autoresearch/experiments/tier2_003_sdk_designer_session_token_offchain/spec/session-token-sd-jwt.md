# SD-JWT Session Token for Off-Chain Proof Reuse

**Version:** 0.1.0  
**Status:** Draft  
**Authors:** Bolyra Protocol Team  
**Date:** 2026-06-19

## 1. Overview

After a successful mutual ZKP handshake (`verifyHandshake()`), the verifier mints
a short-lived **SD-JWT** (Selective Disclosure JWT, per
[draft-ietf-oauth-selective-disclosure-jwt-14](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/))
that binds the verified proof outputs. Subsequent API calls present the compact
token instead of re-running the full ZKP verification.

**Latency impact:** Initial handshake with rapidsnark takes ~2 s; follow-up
calls with `verifySessionToken()` take <1 ms.

## 2. Claim Schema

### 2.1 Required Claims (always visible)

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer identifier. Default: `"bolyra.ai"` |
| `iat` | number | Issued-at (Unix epoch seconds) |
| `exp` | number | Expiration (Unix epoch seconds) |
| `_sd_alg` | string | Hash algorithm for SD digests. Fixed: `"sha-256"` |

### 2.2 Selectively Disclosable Claims

These claims are included as SD-JWT disclosures. The holder can reveal any
subset when presenting the token to a relying party.

| Claim | Type | Description |
|---|---|---|
| `nullifierHash` | string | Per-session nullifier hash from HumanUniqueness proof (hex) |
| `scopeCommitment` | string | Poseidon commitment of the scope bitmask (hex) |
| `humanMerkleRoot` | string | Identity tree root at proof time (hex) |
| `agentCredentialHash` | string | Hash of the agent credential commitment (hex) |
| `modelHash` | string | (Optional) Hash of the AI model that produced the agent proof |
| `operatorDID` | string | (Optional) DID of the agent operator |

### 2.3 Disclosure Format

Each disclosure is a base64url-encoded JSON array:

```
base64url(["<salt>", "<claim_name>", <claim_value>])
```

The JWT payload contains `_sd`: an array of SHA-256 digests of each disclosure.
The full token is:

```
<issuer-signed-jwt>~<disclosure1>~<disclosure2>~...~
```

To selectively disclose, the holder omits disclosures from the `~`-separated
string while the `_sd` digests remain in the JWT for integrity.

## 3. Signing Key Conventions

| Mode | Algorithm | Use Case |
|---|---|---|
| **HMAC-SHA256** | `HS256` | Shared-secret between issuer and single verifier |
| **EdDSA (Ed25519)** | `EdDSA` | Asymmetric — issuer signs, any verifier checks |

Default: `HS256` with a 256-bit shared secret (`Uint8Array[32]`). This is
appropriate when issuer and verifier are the same service. For federated
verification across multiple relying parties, use EdDSA.

## 4. Token Lifecycle

```
  Human + Agent
       |
       v
  proveHandshake()          ~2 s (rapidsnark)
       |
       v
  verifyHandshake()         on-chain / off-chain
       |
       v
  issueSessionToken()       packs claims into SD-JWT
       |
       v
  ┌─────────────────────────────────────────┐
  │  Subsequent API calls:                  │
  │  verifySessionToken(token)    <1 ms     │
  │  Selective disclosure: present only     │
  │  nullifierHash to prove session valid   │
  │  without revealing scope or agent info  │
  └─────────────────────────────────────────┘
       |
       v
  Token expires (default: 300 s)
```

## 5. `issueSessionToken()` Contract

```typescript
function issueSessionToken(
  result: HandshakeResult,
  secret: Uint8Array,          // 32-byte HMAC key or EdDSA private key
  options?: {
    ttlSeconds?: number;       // default: 300, range: [60, 3600]
    disclose?: string[];       // claims to include as disclosures
                               // default: all 4 required disclosable claims
    algorithm?: 'HS256' | 'EdDSA'; // default: 'HS256'
  }
): string;                     // SD-JWT compact serialization
```

## 6. `verifySessionToken()` Contract

```typescript
function verifySessionToken(
  token: string,               // SD-JWT compact serialization
  secret: Uint8Array,          // HMAC key or EdDSA public key
  options?: {
    requiredClaims?: string[]; // claims that MUST be disclosed
    clockToleranceSec?: number; // default: 0
  }
): SessionClaims;              // decoded + verified claims
```

## 7. Security Considerations

- **Token binding:** The SD-JWT is bound to a specific handshake via
  `nullifierHash`. Replaying the token without the original session context
  is detectable by the verifier.
- **Short-lived by default:** 300 s TTL limits exposure window.
- **No on-chain state:** Session tokens are purely off-chain. Revocation
  requires application-layer mechanisms (short TTL recommended over revocation
  lists for simplicity).
- **Selective disclosure privacy:** Relying parties that only need to confirm
  session validity can receive `nullifierHash` alone, without learning the
  agent's credential hash or scope commitment.
- **Salt entropy:** Each disclosure salt is 128 bits of cryptographic randomness
  to prevent dictionary attacks on hashed disclosures.

## 8. Interop Notes (TS ↔ Python)

- Claim names use camelCase in both SDKs (JSON wire format).
- Python `issue_session_token()` / `verify_session_token()` mirror the TS API
  with snake_case function names.
- Both SDKs use SHA-256 for `_sd` digests.
- The `_sd_alg` claim is always `"sha-256"`.
- Tokens minted in TS are verifiable in Python and vice versa when using the
  same shared secret.
