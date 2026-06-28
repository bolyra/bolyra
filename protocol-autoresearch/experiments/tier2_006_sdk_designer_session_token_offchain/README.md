# Session Token Off-Chain Proof Reuse

**Experiment:** `sdk_designer_session_token_offchain`  
**Dimension:** Adoption  
**Priority:** High

## Problem

Every Bolyra API call requires a fresh ZK proof (1-5s). This is the biggest developer complaint and adoption blocker.

## Solution

After `verifyHandshake()` succeeds, mint a short-lived SD-JWT session token binding the verified proof outputs. Subsequent calls present the token instead of re-proving.

## Usage

```typescript
import {
  SessionTokenIssuer,
  SessionTokenVerifier,
} from '@bolyra/sdk';
import { randomBytes } from 'crypto';

// After verifyHandshake() succeeds:
const secret = randomBytes(32); // shared between issuer and verifier

// Mint a session token (default: 5min TTL)
const token = SessionTokenIssuer.mint(handshakeResult, {
  signingKey: secret,
});

// On subsequent requests, verify the token instead of re-proving
const claims = SessionTokenVerifier.verify(token, {
  signingKey: secret,
  requiredClaims: ['nullifierHash', 'agentId'],
});

console.log(claims.nullifierHash); // '0xaabb...'
console.log(claims.agentId);       // '0x4444...'
```

## Selective Disclosure

Only reveal the claims each endpoint needs:

```typescript
// Mint with selective disclosure
const token = SessionTokenIssuer.mint(handshakeResult, {
  signingKey: secret,
  selectiveDisclosureFields: ['nullifierHash'], // only disclose this
});

// Verifier only sees nullifierHash
const claims = SessionTokenVerifier.verify(token, {
  signingKey: secret,
  requiredClaims: ['nullifierHash'],
});
```

## Configuration

| Option | Default | Range | Description |
|---|---|---|---|
| `ttl` | 300 | 60-3600 | Token lifetime in seconds |
| `issuer` | `'bolyra.ai'` | — | Issuer claim |
| `audience` | — | — | Audience claim (optional) |
| `clockSkew` | 30 | — | Verifier clock tolerance (seconds) |

## Error Handling

```typescript
import {
  SessionTokenExpiredError,
  SessionTokenInvalidError,
  SessionTokenClaimMissingError,
} from '@bolyra/sdk';

try {
  const claims = SessionTokenVerifier.verify(token, opts);
} catch (err) {
  if (err instanceof SessionTokenExpiredError) {
    // Re-prove and mint a new token
  } else if (err instanceof SessionTokenClaimMissingError) {
    // Request full disclosure from presenter
  } else if (err instanceof SessionTokenInvalidError) {
    // Tampered or malformed token
  }
}
```

## Files

| File | Description |
|---|---|
| `sdk/src/session/types.ts` | Type definitions |
| `sdk/src/session/errors.ts` | Typed error classes |
| `sdk/src/session/SessionTokenIssuer.ts` | Mints SD-JWT tokens from HandshakeResult |
| `sdk/src/session/SessionTokenVerifier.ts` | Verifies tokens, checks expiry and claims |
| `sdk/src/session/index.ts` | Barrel exports |
| `sdk/src/index.ts` | Re-exports session module from SDK entry |
| `sdk/test/session/SessionTokenIssuer.test.ts` | Issuer unit tests |
| `sdk/test/session/SessionTokenVerifier.test.ts` | Verifier unit tests |
| `sdk/test/session/integration.test.ts` | End-to-end round-trip test |
| `spec/session-token-offchain.md` | Protocol specification |

## Spec

See [spec/session-token-offchain.md](spec/session-token-offchain.md) for the full protocol specification including claim set, TTL policy, replay prevention, and security considerations.
