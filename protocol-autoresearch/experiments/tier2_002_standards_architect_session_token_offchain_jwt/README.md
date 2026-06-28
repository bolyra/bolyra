# Bolyra Session Token (JWT)

JWT-based off-chain session tokens for verified Bolyra handshakes.

## What This Is

After a successful on-chain Bolyra ZKP handshake, the relayer issues a
short-lived JWT carrying the handshake's public signals (`humanNullifier`,
`agentNullifier`, `sessionNonce`, `scopeCommitment`). Downstream services
validate this bearer token instead of re-verifying the ZKP on every request.

## Artifacts

| File | Description |
|---|---|
| `spec/bolyra-session-token-jwt-01.md` | JWT profile specification with ABNF claim definitions |
| `sdk/src/types/session-token.ts` | TypeScript interfaces: `BolyraJWTPayload`, `SessionTokenOptions`, `VerifiedSessionClaims` |
| `sdk/src/session-token.ts` | Reference implementation: `issueSessionToken()`, `verifySessionToken()` |
| `sdk/test/session-token.test.ts` | 17 test vectors covering valid tokens, expiry, tampering, delegation chains, and more |
| `docs/session-token-integration.md` | Integration guide for Express, LangChain, and Vercel AI SDK |

## Quick Start

```typescript
import { issueSessionToken, verifySessionToken } from '@bolyra/sdk';
import { generateKeyPair } from 'jose';

// Generate relayer keys (do this once, store securely)
const { privateKey, publicKey } = await generateKeyPair('ES256');

// After successful on-chain handshake verification:
const token = await issueSessionToken(
  {
    humanNullifier: '0xaabb...1234',
    agentNullifier: '0x1122...5678',
    sessionNonce:   '0xdead...beef',
    scopeCommitment: '0x0000...00ff',
    verified: true,
  },
  privateKey,
  {
    chainId: 84532,
    verifierContract: '0x1234...5678',
    ttlSeconds: 300, // 5 minutes (default)
  },
);

// Verify on subsequent API calls:
const session = await verifySessionToken(token, publicKey);
console.log(session.payload.humanNullifier); // '0xaabb...1234'
console.log(session.active);                  // true
console.log(session.remainingSeconds);        // ~299
```

## JWT Structure

- **Header**: `{ alg: "ES256" | "EdDSA", typ: "bolyra+jwt" }`
- **Payload**: All four handshake signals + delegation chain + chain binding
- **TTL**: Default 300s, max 3600s
- **Signing**: ES256 (P-256 ECDSA) or EdDSA (Ed25519)

## Running Tests

```bash
cd sdk && npx mocha --require ts-node/register test/session-token.test.ts
```

## Dependencies

- `jose` ^5.x — JWT sign/verify (ES256, EdDSA)
- `@bolyra/sdk` — handshake types
