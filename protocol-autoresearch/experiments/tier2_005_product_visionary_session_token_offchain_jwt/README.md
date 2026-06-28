# Off-chain session token (JWT) after on-chain handshake

After a successful on-chain handshake verification, emit a signed JWT session token that encodes the verified scope, nullifiers, and expiry. Subsequent API calls within the session present this JWT instead of re-proving on-chain. This is the critical path to production adoption: no agentic commerce platform will pay gas per API call. Implement a SessionTokenIssuer in the SDK that takes handshake proof outputs and returns a compact JWT, plus a verifySessionToken() function that checks signature, expiry, and scope without touching the chain. Add a spec section defining the JWT claims (scope_commitment, human_nullifier, agent_nullifier, session_nonce, iat, exp).

## Status

Placeholder — awaiting implementation.
