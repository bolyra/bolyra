# Session Tokens — How-To Guide

## Overview

After a successful `verifyHandshake()`, the relying party (RP) mints a **Bolyra Session Token** (BST) — a short-lived JWT that downstream middleware validates with a single signature check, without calling back to the chain.

## Quick Start (3 lines)

```typescript
import { verifyHandshake, mintSessionToken, verifySessionToken } from '@bolyra/sdk';

// 1. Verify the on-chain handshake
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 2. Mint a session token
const token = await mintSessionToken(result, rpSigningKey, { ttlSeconds: 3600 });

// 3. Attach as Bearer header in subsequent requests
fetch('/api/protected', {
  headers: { Authorization: `Bearer ${token}` },
});
```

## Validating at the Relying Party

```typescript
import { verifySessionToken, BolyraSessionError } from '@bolyra/sdk';

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const session = await verifySessionToken(
      token,
      rpPublicKey,
      expectedSessionNonce,  // optional: enforce nonce binding
    );

    req.session = session.payload;
    next();
  } catch (err) {
    if (err instanceof BolyraSessionError) {
      const status = err.code === 'SCOPE_INSUFFICIENT' ? 403 : 401;
      return res.status(status).json({ error: err.code, message: err.message });
    }
    return res.status(500).json({ error: 'Internal error' });
  }
}
```

## Checking Scope Without Re-Verification

If you've already verified the token and just need to check permissions for a specific endpoint:

```typescript
import { extractScopeFromToken } from '@bolyra/sdk';

const scopeCommitment = extractScopeFromToken(token);
// Resolve scopeCommitment against your permission records
```

## Key Generation

The RP needs an asymmetric key pair for signing tokens. EdDSA (Ed25519) is recommended:

```typescript
import { generateKeyPair, exportJWK } from 'jose';

// Generate once, store securely
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const rpSigningKey = await exportJWK(privateKey);
const rpPublicKey = await exportJWK(publicKey);
```

ES256 (P-256) is also supported for environments lacking Ed25519:

```typescript
const { privateKey, publicKey } = await generateKeyPair('ES256');
const token = await mintSessionToken(result, await exportJWK(privateKey), {
  algorithm: 'ES256',
});
```

## Session Lifetime Recommendations

| Scope | Max TTL | Rationale |
|-------|---------|----------|
| `READ_DATA` only | 24 hours | Low-risk, reduces re-auth friction |
| `WRITE_DATA` | 4 hours | Moderate risk |
| Financial (`FINANCIAL_SMALL/MEDIUM/UNLIMITED`) | 1 hour | High-value operations |
| `SIGN_ON_BEHALF` / `SUB_DELEGATE` | 15 minutes | Highest privilege |
| `ACCESS_PII` | 1 hour | Regulatory compliance |

**Hard limits:** minimum 30 seconds, maximum 24 hours (86400 seconds).

## Error Handling

| Error Code | HTTP | Meaning |
|-----------|------|---------|
| `EXPIRED_SESSION` | 401 | Token has expired — re-run handshake |
| `NONCE_MISMATCH` | 401 | Token bound to a different session |
| `SCOPE_INSUFFICIENT` | 403 | Permission bits don't cover this action |
| `INVALID_SIGNATURE` | 401 | Bad signature, wrong key, or malformed token |

## Media Type

The BST uses the media type `application/bolyra-session+jwt`. Set this in API responses:

```typescript
import { BOLYRA_SESSION_MEDIA_TYPE } from '@bolyra/sdk';

res.setHeader('Content-Type', BOLYRA_SESSION_MEDIA_TYPE);
res.send(token);
```

## Key Discovery

The RP's public key is discoverable via its `did:bolyra` DID Document:

```json
{
  "id": "did:bolyra:verifier123",
  "verificationMethod": [{
    "id": "did:bolyra:verifier123#key-1",
    "type": "JsonWebKey2020",
    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
  }],
  "assertionMethod": ["did:bolyra:verifier123#key-1"]
}
```

See [spec/did-method-bolyra.md](../spec/did-method-bolyra.md) for the full DID method specification.
