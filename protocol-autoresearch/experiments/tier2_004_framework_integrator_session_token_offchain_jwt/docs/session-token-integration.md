# Session Token Integration Guide

This guide shows how to integrate Bolyra session tokens with LangChain and
CrewAI. The pattern is: **one-time ZKP handshake → mint JWT → bearer token
on subsequent tool calls**.

## Quick Start (TypeScript)

```typescript
import {
  verifyHandshake,
  handshakeToSessionToken,
  verifySessionToken,
} from '@bolyra/sdk';
import { generateKeyPair } from 'jose';

// 1. Generate verifier's ES256 key pair (once, at startup)
const { privateKey, publicKey } = await generateKeyPair('ES256');

// 2. On-chain handshake verification (once per session)
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 3. Mint session token (~0.5ms)
const jwt = await handshakeToSessionToken(result, privateKey, {
  ttlSeconds: 3600,
  audience: 'langchain',
});

// 4. Verify per tool call (~0.5ms instead of ~200ms re-proving)
const claims = await verifySessionToken(jwt, publicKey);
console.log(claims.nullifier); // nullifierHash
console.log(claims.scope);     // scopeCommitment
console.log(claims.expiry);    // Unix timestamp
```

## LangChain Integration (Python)

Pass the JWT as a bearer token in HTTP headers when calling tools through
a Bolyra-protected gateway:

```python
import requests

BOLYRA_GATEWAY = "https://gateway.bolyra.ai"

def call_tool_with_session(tool_name: str, payload: dict, jwt: str) -> dict:
    """Call a Bolyra-protected tool using a session JWT."""
    resp = requests.post(
        f"{BOLYRA_GATEWAY}/tools/{tool_name}",
        json=payload,
        headers={"Authorization": f"Bearer {jwt}"},
    )
    resp.raise_for_status()
    return resp.json()

# Usage in a LangChain tool:
from langchain.tools import tool

@tool
def lookup_member(member_id: str) -> str:
    """Look up a credit union member by ID."""
    result = call_tool_with_session(
        "member_lookup",
        {"member_id": member_id},
        session_jwt,  # obtained from one-time handshake
    )
    return result["summary"]
```

### LangChain Callback (Auto-Inject)

```python
from langchain.callbacks.base import BaseCallbackHandler

class BolyraSessionCallback(BaseCallbackHandler):
    def __init__(self, jwt: str):
        self.jwt = jwt

    def on_tool_start(self, serialized, input_str, **kwargs):
        kwargs.setdefault("metadata", {})["bolyra_jwt"] = self.jwt

# Attach to your agent:
agent.run("...", callbacks=[BolyraSessionCallback(jwt)])
```

## CrewAI Integration (Python)

```python
from crewai import Agent, Task, Crew

# After handshake, attach session claims to agent context
agent = Agent(
    role="Financial Analyst",
    goal="Analyze member portfolio",
    backstory="Authenticated via Bolyra ZKP handshake",
    tools=[lookup_member],  # tools auto-inject the JWT
)

task = Task(
    description="Look up member 12345 and summarize their portfolio",
    agent=agent,
    context={"bolyra_session": {
        "jwt": session_jwt,
        "nullifier": claims["nullifier"],
        "scope": claims["scope"],
    }},
)

crew = Crew(agents=[agent], tasks=[task])
result = crew.kickoff()
```

## Token Lifetime Recommendations

| Scenario | Recommended TTL | Rationale |
|----------|----------------|-----------|
| Multi-tool agent chain | 3600s (1 hr) | Default. Covers most task executions. |
| Financial operations | 300s (5 min) | Limits bearer token exposure. |
| Interactive human-in-loop | 1800s (30 min) | Balances convenience and security. |

## Revocation

Session tokens are short-lived by design. For immediate revocation:

1. **Nullifier registry** (on-chain): Mark the nullifier as consumed in
   `BolyraRegistry`. Any subsequent token verification that checks
   on-chain state will reject it.
2. **Process-local blocklist**: Maintain an in-memory set of revoked
   token identifiers (e.g., `jti` if added) for sub-second revocation
   within a single process.
3. **Key rotation**: Rotate the verifier's ES256 key pair. All tokens
   signed with the old key become unverifiable.

## Security Notes

- **The JWT is a cache, not a replacement for ZK proofs.** The on-chain
  nullifier check remains the ground truth for identity verification.
- **Always use TLS** for token transport. JWTs are bearer credentials.
- **Never persist tokens to disk.** Store only in memory for the session
  duration.
- **Re-verify on-chain** for high-value operations (financial transactions
  above threshold, PII access) even if a valid session token exists.
