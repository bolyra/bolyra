# @bolyra/sdk Quickstart

## Installation

```bash
npm install @bolyra/sdk
```

## Basic Flow: Human + Agent Handshake

```typescript
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from '@bolyra/sdk';

// 1. Create identities
const human = await createHumanIdentity(mySecret);
const agent = await createAgentCredential(modelHash, operatorKey, permissions, expiry);

// 2. Prove and verify
const { humanProof, agentProof } = await proveHandshake(human, agent);
const result = await verifyHandshake(humanProof, agentProof, nonce);
// result.verified === true
```

## Session Tokens: Off-Chain Proof Reuse

After a successful handshake, mint an **SD-JWT session token** to avoid
re-running the full ZKP verification on every subsequent API call.

```typescript
import { issueSessionToken, verifySessionToken } from '@bolyra/sdk';
import { randomBytes } from 'crypto';

// Shared secret between issuer and verifier (32 bytes)
const sessionSecret = randomBytes(32);

// One-time: mint after handshake
const token = issueSessionToken(handshakeResult, sessionSecret, {
  ttlSeconds: 300, // 5 minutes (default)
});

// Subsequent calls: verify the token (~<1 ms)
const claims = verifySessionToken(token, sessionSecret);
console.log(claims.nullifierHash); // 0xaabb...
console.log(claims.iss);           // 'bolyra.ai'
```

### Selective Disclosure

SD-JWT lets you reveal only the claims the relying party needs:

```typescript
// Only include nullifierHash in the token disclosures
const token = issueSessionToken(handshakeResult, sessionSecret, {
  disclose: ['nullifierHash'],
});

// Verifier gets nullifierHash but NOT scopeCommitment or agentCredentialHash
const claims = verifySessionToken(token, sessionSecret);
claims.nullifierHash;       // '0xaabb...'
claims.scopeCommitment;     // undefined
claims.agentCredentialHash; // undefined
```

### Requiring Specific Claims

```typescript
// Verifier requires scopeCommitment to be disclosed
const claims = verifySessionToken(token, sessionSecret, {
  requiredClaims: ['scopeCommitment'],
});
// Throws BolyraSessionError('CLAIMS_MISSING') if not disclosed
```

### Latency Comparison

| Operation | Latency | When to use |
|---|---|---|
| `proveHandshake()` + `verifyHandshake()` | ~2 s (rapidsnark) | First interaction — establishes trust |
| `verifySessionToken()` | <1 ms | Subsequent calls within the session |

The session token is a signed JWT with selective disclosure (SD-JWT).
It binds the verified nullifier, scope, and Merkle root so the verifier
can trust subsequent calls without re-running the ZKP circuit.

### Python SDK

```python
from bolyra import issue_session_token, verify_session_token, HandshakeResult

result = HandshakeResult(
    verified=True,
    nullifier_hash="0xaabb...",
    human_merkle_root="0x1111...",
    scope_commitment="0x3333...",
    agent_credential_hash="0x4444...",
)

secret = os.urandom(32)
token = issue_session_token(result, secret, ttl_seconds=300)
claims = verify_session_token(token, secret)
```
