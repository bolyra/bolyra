# Session Tokens: Reducing Per-Call Overhead

After a successful on-chain `verifyHandshake()`, the verifier mints a short-lived
JWT (EdDSA-signed, 5-minute TTL) containing the handshake's binding claims.
Subsequent tool calls present only the JWT instead of raw ZK proofs.

## Flow

```
┌──────────┐     verifyHandshake()      ┌──────────┐
│  Agent   │ ──── humanProof + ─────────▶│ Verifier │
│          │      agentProof + nonce     │ (on-chain)│
└──────────┘                             └────┬─────┘
                                              │ valid ✓
                                              ▼
                                   mintSessionToken()
                                       EdDSA JWT
                                              │
┌──────────┐     Authorization: Bearer JWT   │
│  Agent   │ ◀──────────────────────────────┘
│          │
│  call 1  │ ── JWT ──▶ verifySessionToken() ── ✓ (0.1ms)
│  call 2  │ ── JWT ──▶ verifySessionToken() ── ✓ (0.1ms)
│  call N  │ ── JWT ──▶ verifySessionToken() ── ✓ (0.1ms)
└──────────┘
```

## Claim Schema

| Claim | Type | Description |
|-------|------|-------------|
| `nullifierHash` | `string` | Human uniqueness nullifier from the handshake |
| `scopeCommitment` | `string` | Poseidon commitment to the granted scope bitmap |
| `sessionNonce` | `string` | The handshake nonce — binds the JWT to the session |
| `iat` | `number` | Issued-at Unix timestamp |
| `exp` | `number` | Expiry Unix timestamp (iat + TTL) |
| `iss` | `string` | Issuer — always `"bolyra.ai"` |

## TTL Rationale

- **Default: 300s (5 minutes)** — long enough for a typical multi-tool agent
  chain (10–50 calls), short enough to limit token theft exposure.
- **Min: 60s** — enforced to prevent degenerate single-call tokens.
- **Max: 900s (15 minutes)** — upper bound per the spec. Longer sessions
  should re-verify on-chain.

## TypeScript Usage

```typescript
import {
  verifyHandshake,
  mintSessionToken,
  verifySessionToken,
} from '@bolyra/sdk';
import { generateKeyPair, exportJWK } from 'jose';

// One-time: generate verifier's Ed25519 key pair
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const privateJwk = await exportJWK(privateKey);
const publicJwk = await exportJWK(publicKey);

// 1. On-chain handshake verification (once)
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 2. Mint session token (~0.3ms)
const jwt = await mintSessionToken(result, privateJwk);

// 3. Verify per tool call (~0.1ms)
const claims = await verifySessionToken(jwt, publicJwk);
console.log(claims.nullifierHash, claims.scopeCommitment);
```

## Python Usage

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bolyra import mint_session_token, verify_session_token
from bolyra.session import HandshakeVerifyResult

# Generate verifier key pair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# After successful verifyHandshake()
result = HandshakeVerifyResult(
    valid=True,
    nullifier_hash="0xaabb...",
    scope_commitment="0x1122...",
    session_nonce="0xdead...",
)

# Mint & verify
token = mint_session_token(result, private_key)
claims = verify_session_token(token, public_key)
print(claims.nullifier_hash, claims.scope_commitment)
```

## Framework Integration Snippets

### LangChain CallbackManager

```python
from langchain.callbacks.base import BaseCallbackHandler

class BolyraAuthCallback(BaseCallbackHandler):
    def __init__(self, session_jwt: str, public_key):
        self.jwt = session_jwt
        self.public_key = public_key

    def on_tool_start(self, serialized, input_str, **kwargs):
        claims = verify_session_token(self.jwt, self.public_key)
        # Attach claims to tool context
        kwargs.setdefault("metadata", {})["bolyra_claims"] = claims
```

### CrewAI Context

```python
from crewai import Agent, Task

claims = verify_session_token(jwt_token, public_key)

agent = Agent(
    role="Analyst",
    goal="Process financial data",
    context={"bolyra_session": {
        "nullifier": claims.nullifier_hash,
        "scope": claims.scope_commitment,
        "expires": claims.exp,
    }},
)
```

### AutoGen ConversableAgent

```python
from autogen import ConversableAgent

claims = verify_session_token(jwt_token, public_key)

agent = ConversableAgent(
    name="bolyra_agent",
    system_message=f"Authenticated session. Scope: {claims.scope_commitment}. "
                   f"Expires: {claims.exp}.",
)
```

## Security Notes

- **Token binding**: The `sessionNonce` in the JWT MUST match the nonce used in
  the original `verifyHandshake()` call. This prevents cross-session replay.
- **Replay within session**: The JWT is bearer-scoped — anyone with the token
  can use it until expiry. Use TLS for transport and keep TTLs short.
- **Key management**: The verifier's Ed25519 private key must be kept secret.
  Generate per deployment; rotate on compromise.
- **No on-chain state**: Session tokens are purely off-chain. They do not
  modify or query any smart contract state after initial verification.
