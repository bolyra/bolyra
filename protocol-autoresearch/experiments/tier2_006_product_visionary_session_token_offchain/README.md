# Off-chain session token with batched on-chain checkpoints

After a successful on-chain handshake, mint a short-lived off-chain session token (JWT-shaped, embedding nullifierHash + scopeCommitment + expiry). Subsequent API calls within the session verify the token locally without hitting the chain. Batch session roots are posted on-chain at configurable intervals (e.g., every 100 sessions or 10 minutes). This is the single biggest adoption blocker for high-throughput agentic commerce — no one will pay gas per tool call.

## Status

Placeholder — awaiting implementation.
