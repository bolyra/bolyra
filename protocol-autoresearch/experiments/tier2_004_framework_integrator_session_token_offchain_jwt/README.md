# Off-chain JWT Session Token from Verified Handshake

**Experiment:** `framework_integrator_session_token_offchain_jwt`
**Dimension:** Adoption
**Priority:** High
**Persona:** Framework Integrator

## Problem

Framework integrations (LangChain, CrewAI, AutoGen) expect sub-100ms auth
checks per tool invocation. Re-generating and verifying ZK proofs on every
call (~200ms + 1.5KB payload) is the single biggest adoption blocker for
multi-tool agent chains making 10–200 calls per task.

## Solution

After a successful on-chain `verifyHandshake()`, the SDK mints a short-lived
JWT (ES256, 1-hour default TTL) binding `nullifierHash` (as `sub`) and
`scopeCommitment` (as `scope`). Subsequent calls present only the JWT,
reducing per-call overhead to a single ECDSA signature check (~0.5ms).

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `sdk/src/session.ts` | SDK | `handshakeToSessionToken()` + `verifySessionToken()` using jose ES256 |
| `sdk/src/index.ts.patch` | SDK | Re-exports for public API surface |
| `sdk/src/types.ts.patch` | SDK | JWT payload type definition |
| `sdk/test/session.test.ts` | Test | Mocha/Chai: round-trip, expiry, tampering, key mismatch |
| `spec/session-token-schema.md` | Spec | JWT payload schema, key requirements, security model |
| `docs/session-token-integration.md` | Docs | LangChain + CrewAI integration guide with code snippets |

## Usage

```typescript
import {
  verifyHandshake,
  handshakeToSessionToken,
  verifySessionToken,
} from '@bolyra/sdk';
import { generateKeyPair } from 'jose';

// Generate verifier's ES256 key pair
const { privateKey, publicKey } = await generateKeyPair('ES256');

// 1. One-time on-chain verification
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 2. Mint session token (~0.5ms)
const jwt = await handshakeToSessionToken(result, privateKey, {
  ttlSeconds: 3600,
  audience: 'langchain',
});

// 3. Verify per tool call (~0.5ms)
const claims = await verifySessionToken(jwt, publicKey);
// { nullifier: '0xaabb...', scope: '0x1122...', expiry: 1750000000 }
```

## Dependencies

- `jose >= 5.0` (JWT sign/verify, ES256, Web Crypto API compatible)
- Node 18+ Web Crypto API (`SubtleCrypto`) for `CryptoKey` handling
- Existing `verifyHandshake()` output shape (`nullifierHash`, `scopeCommitment`)

## Testing

```bash
cd sdk && npm install && npm run build && npm test
```

## Key Design Decisions

- **ES256 over EdDSA**: P-256 ECDSA has universal Web Crypto API support
  across Node 18+, browsers, and Cloudflare Workers without polyfills.
  EdDSA (Ed25519) Web Crypto support is newer (Node 20+, limited browser).
- **CryptoKey over JWK**: Uses native `CryptoKey` objects from Web Crypto
  API directly, avoiding serialization overhead and key material exposure.
- **`sub` = nullifierHash**: Follows JWT conventions where `sub` identifies
  the subject. The nullifier is the unique session identifier.
- **Default 1-hour TTL**: Covers a full multi-tool agent task execution
  (10–200 calls) without requiring re-verification.
- **Audience claim**: Enables verifiers to scope tokens to specific
  frameworks (`langchain`, `crewai`, or wildcard `*`).
