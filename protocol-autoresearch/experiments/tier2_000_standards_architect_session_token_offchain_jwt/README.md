# JWT-Encoded Off-Chain Session Token for Verified Handshakes

**Experiment ID:** `standards_architect_session_token_offchain_jwt`
**Dimension:** standards
**Priority:** high

## Summary

Defines a compact JWT profile (RFC 7519) for encoding verified Bolyra handshake
results off-chain. After `verifyHandshake()` succeeds on-chain, the relayer mints
a short-lived ES256 JWT with:

- `iss` = registry contract address
- `sub` = nullifierHash
- `scope` = scopeCommitment (base64url)
- `nonce` = sessionNonce
- `bolyra_root` = humanMerkleRoot
- `jti` = UUID for replay prevention

JOSE header extensions `x-bolyra-registry` and `x-bolyra-chain-id` bind the
token to a specific on-chain registry and EVM network.

## Artifacts

| File | Description |
|---|---|
| `spec/draft-bolyra-mutual-zkp-auth-01-section7.md` | JWT profile spec (Section 7) |
| `sdk/src/sessionToken.ts` | `encodeSessionToken()` and `verifySessionToken()` |
| `sdk/src/index.ts` | Public API re-exports |
| `sdk/test/sessionToken.test.ts` | 14 unit tests |
| `sdk/QUICKSTART.md` | Integration guide with code snippets |

## Quick Start

```typescript
import { encodeSessionToken, verifySessionToken } from '@bolyra/sdk';
import { generateKeyPair } from 'jose';

const { privateKey, publicKey } = await generateKeyPair('ES256');

const jwt = await encodeSessionToken(handshakeResult, privateKey, 900, 84532);
const claims = await verifySessionToken(jwt, publicKey, registryAddr, 84532);
```

## Running Tests

```bash
cd sdk && npx mocha --require ts-node/register test/sessionToken.test.ts
```

## Dependencies

- `jose` ^5.x — ES256 JWT sign/verify
- `@bolyra/sdk` — HandshakeResult types
- Node.js `crypto` — `randomUUID()` for jti
