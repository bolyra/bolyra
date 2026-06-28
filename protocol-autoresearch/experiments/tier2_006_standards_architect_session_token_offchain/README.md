# Experiment: Off-chain Session Token Format (`standards_architect_session_token_offchain`)

## Summary

Defines `application/bolyra-session+jwt` — a compact JWS-based session token format for off-chain use after on-chain Bolyra handshake verification. The token cryptographically binds the four handshake public signals (`humanNullifier`, `agentNullifier`, `sessionNonce`, `scopeCommitment`) into a short-lived bearer credential.

## Problem

After a successful on-chain ZKP handshake, every subsequent API call currently requires either re-verification or an ad-hoc session mechanism. There is no standardized bearer token format that preserves the cryptographic binding to the original handshake.

## Solution

A JWS Compact Serialization token with:
- **Header**: `typ: bolyra-session+jwt`, `alg: EdDSA` (or `ES256`)
- **Payload**: `humanNullifier`, `agentNullifier`, `sessionNonce`, `scopeCommitment`, `iat`, `exp`, `iss`
- **Signature**: Asymmetric (EdDSA/ES256) — never symmetric

The ZKP already happened on-chain. The BST is the RP's attestation that it was valid.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/session-token-format.md` | spec | Normative specification with ABNF, claim semantics, error codes |
| `spec/iana-media-type-registration.md` | spec | Draft IANA registration per RFC 6838 |
| `sdk/src/types/session.ts` | types | `BolyraSessionPayload`, `BolyraSessionHeader`, `SessionTokenOptions`, `VerifiedSession` |
| `sdk/src/session-token.ts` | SDK | `mintSessionToken()`, `verifySessionToken()`, `extractScopeFromToken()` |
| `sdk/test/session-token.test.ts` | test | Round-trip, expiry, tampering, nonce mismatch, scope extraction |
| `docs/session-tokens.md` | docs | How-to guide with 3-line quickstart |

## Usage

```typescript
import { mintSessionToken, verifySessionToken } from './sdk/src/session-token.js';
import { generateKeyPair, exportJWK } from 'jose';

// Generate RP key pair
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const privJwk = await exportJWK(privateKey);
const pubJwk = await exportJWK(publicKey);

// After verifyHandshake()
const handshakeResult = {
  humanNullifier: '0xaabb...0044',
  agentNullifier: '0x1122...8888',
  sessionNonce:   '0xdead...beef',
  scopeCommitment:'0x0000...00ff',
  verified: true,
};

// Mint
const token = await mintSessionToken(handshakeResult, privJwk, { ttlSeconds: 3600 });

// Verify
const session = await verifySessionToken(token, pubJwk);
console.log(session.payload.humanNullifier); // 0xaabb...0044
console.log(session.active);                 // true
console.log(session.remainingSeconds);        // ~3600
```

## Running Tests

```bash
npm install jose
npx mocha --require ts-node/register sdk/test/session-token.test.ts
```

## Dependencies

- `jose` — JWS compact serialization, EdDSA/ES256 signing
- `verifyHandshake()` return type must expose `humanNullifier`, `agentNullifier`, `sessionNonce`, `scopeCommitment`
- `did:bolyra` DID method spec for issuer key discovery
- 8-bit cumulative permission encoding for `scopeCommitment` derivation
