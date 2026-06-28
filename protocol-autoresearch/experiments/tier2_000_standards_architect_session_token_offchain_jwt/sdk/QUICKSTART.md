# Minting and Verifying Off-Chain Session Tokens

After a successful on-chain `verifyHandshake()`, mint a short-lived JWT to
avoid re-verifying the ZKP on every subsequent API call.

## Issuing a Session Token (Relayer Side)

```typescript
import { encodeSessionToken } from '@bolyra/sdk';
import { generateKeyPair } from 'jose';

// Generate relayer ES256 key pair (do this once, store securely)
const { privateKey, publicKey } = await generateKeyPair('ES256');

// After on-chain handshake verification succeeds:
const handshakeResult = {
  nullifierHash:   '0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344',
  scopeCommitment: '0x00000000000000000000000000000000000000000000000000000000000000ff',
  sessionNonce:    '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
  humanMerkleRoot: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  registryAddress: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
  verified: true,
};

const jwt = await encodeSessionToken(
  handshakeResult,
  privateKey,
  900,    // 15-minute TTL (default)
  84532,  // Base Sepolia chain ID
);
// Send jwt to the client as a bearer token
```

## Verifying a Session Token (API Gateway Side)

```typescript
import { verifySessionToken } from '@bolyra/sdk';

// In your API middleware:
const bearerToken = req.headers.authorization?.replace('Bearer ', '');

try {
  const claims = await verifySessionToken(
    bearerToken,
    relayerPublicKey,
    '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC', // expected registry
    84532, // expected chain ID
  );

  // claims.sub         — nullifierHash (user identity)
  // claims.nonce       — sessionNonce (replay binding)
  // claims.scope       — scopeCommitment (base64url)
  // claims.bolyra_root — humanMerkleRoot
  // claims.jti         — unique token ID

  req.bolyraSession = claims;
} catch (err) {
  if (err.code === 'TOKEN_EXPIRED') {
    res.status(401).json({ error: 'Session expired, re-authenticate' });
  } else {
    res.status(403).json({ error: 'Invalid session token' });
  }
}
```

## Key Points

- **Algorithm**: ES256 (P-256 ECDSA) only
- **Default TTL**: 15 minutes (configurable 60s–3600s)
- **Header extensions**: `x-bolyra-registry` and `x-bolyra-chain-id` bind the token to a specific on-chain registry and network
- **Revocation**: Stateless (rely on short TTL); `jti` enables future blocklist
- **Scope encoding**: `scopeCommitment` is base64url-encoded in the `scope` claim
