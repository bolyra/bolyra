# Session Token Quickstart

After a successful Bolyra ZKP handshake, issue a short-lived JWT so
relying parties can verify identity without on-chain queries.

## 1. Install

```bash
npm install @bolyra/sdk jose
```

## 2. Issue a Session Token

```typescript
import { proveHandshake, verifyHandshake, issueSessionToken } from '@bolyra/sdk';
import { generateKeyPair, exportJWK } from 'jose';

// 1. Run the handshake (on-chain verification)
const humanProof = await proveHandshake(human, agent, nonce);
const agentProof = await proveHandshake(agent, human, nonce);
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 2. Generate a signing key (do this once, store securely)
const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const signingKey = await exportJWK(privateKey);

// 3. Issue the session token
const token = await issueSessionToken(result, signingKey, {
  ttlSeconds: 300,           // 5 minutes (default)
  issuer: 'https://verify.bolyra.ai',
  verificationTxHash: '0x1234...ef90',  // optional: on-chain tx
  permissions: 7,            // optional: READ + WRITE + FINANCIAL_SMALL
});

console.log(token);
// eyJhbGciOiJFZERTQSIsInR5cCI6ImJvbHlyYStqd3QiLCJ2dHgiOiIweDEyMzQuLi4ifQ...
```

## 3. Verify a Session Token (Relying Party)

```typescript
import { verifySessionToken } from '@bolyra/sdk';
import { exportJWK } from 'jose';

// The relying party only needs the issuer's public key
const publicKey = await exportJWK(issuerPublicKey);

try {
  const claims = await verifySessionToken(token, publicKey, {
    issuer: 'https://verify.bolyra.ai',
    expectedScope: expectedScopeCommitment,  // optional
  });

  console.log('Human:', claims.sub);           // humanNullifier
  console.log('Agent:', claims['bolyra.agn']); // agentNullifier
  console.log('Scope:', claims['bolyra.scp']); // scopeCommitment
  console.log('Nonce:', claims['bolyra.nonce']);
} catch (err) {
  if (err.code === 'TOKEN_EXPIRED') console.error('Token expired');
  if (err.code === 'NONCE_REPLAYED') console.error('Replay detected');
  if (err.code === 'SCOPE_MISMATCH') console.error('Wrong scope');
}
```

## 4. Custom Nonce Store (Production)

The default in-memory nonce store works for single-process servers.
For production, implement the `NonceStore` interface:

```typescript
import type { NonceStore } from '@bolyra/sdk';
import Redis from 'ioredis';

class RedisNonceStore implements NonceStore {
  constructor(private redis: Redis) {}

  async checkAndConsume(nonce: string, expiresAt: number): Promise<boolean> {
    const key = `bolyra:nonce:${nonce}`;
    const ttl = Math.max(1, expiresAt - Math.floor(Date.now() / 1000));
    // SET NX returns null if key already exists (= replayed)
    const result = await this.redis.set(key, '1', 'EX', ttl, 'NX');
    return result === null; // true = replayed, false = fresh
  }
}

const store = new RedisNonceStore(new Redis());
const claims = await verifySessionToken(token, publicKey, {
  nonceStore: store,
});
```

## 5. OAuth 2.0 DPoP Integration

Bind the session token to a DPoP proof per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449):

```typescript
// 1. The authorization server provides a DPoP nonce
const dpopNonce = authServer.getDpopNonce();

// 2. Use the DPoP nonce as the sessionNonce in proveHandshake()
const result = await verifyHandshake(humanProof, agentProof, dpopNonce);

// 3. The resulting bolyra.nonce in the JWT is now cryptographically
//    bound to the DPoP proof — the RP can cross-check both.
const token = await issueSessionToken(result, signingKey);
```

## 6. Auditing the On-Chain Transaction

When the `vtx` header is present, resolve the on-chain transaction:

```typescript
import { decodeProtectedHeader } from 'jose';
import { ethers } from 'ethers';

const header = decodeProtectedHeader(token);
if (header.vtx) {
  const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
  const tx = await provider.getTransaction(header.vtx as string);
  console.log('Verified on-chain at block:', tx?.blockNumber);
}
```

## Token Anatomy

```
┌─────────────────────────────────────────────────┐
│ JOSE Header                                     │
│   alg: EdDSA                                    │
│   typ: bolyra+jwt                               │
│   vtx: 0x1234...ef90 (optional)                 │
├─────────────────────────────────────────────────┤
│ Payload                                         │
│   sub:          humanNullifier                  │
│   iss:          https://verify.bolyra.ai        │
│   iat:          1750000000                       │
│   exp:          1750000300                       │
│   jti:          f47ac10b-...                     │
│   bolyra.agn:   agentNullifier                  │
│   bolyra.scp:   scopeCommitment                 │
│   bolyra.nonce: sessionNonce                    │
│   bolyra.vtx:   0x1234...ef90 (optional)        │
│   bolyra.perm:  7 (optional)                    │
├─────────────────────────────────────────────────┤
│ Signature (EdDSA / ES256)                       │
└─────────────────────────────────────────────────┘
```

## Security Notes

- **Max TTL: 900 seconds** — tokens cannot live longer than 15 minutes.
- **Nonce replay detection** is mandatory; always provide a `NonceStore`.
- **Nullifier linkability** — `sub` and `bolyra.agn` are deterministic;
  treat them as pseudonymous identifiers.
- **vtx is informational** — never skip signature verification because
  a `vtx` header is present.
