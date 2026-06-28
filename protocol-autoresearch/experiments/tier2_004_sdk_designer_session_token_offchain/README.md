# SD-JWT session tokens for off-chain proof reuse

Every API call currently requires a fresh ZK proof (1-5s). After verifyHandshake() succeeds, the verifier should mint a compact SD-JWT token binding nullifierHash, scopeCommitment, and expiry with selective disclosure and a configurable TTL (60-3600s). Ship `SessionTokenIssuer.mint(handshakeResult)` and `SessionTokenVerifier.verify(token, { requiredClaims })` in the SDK. This eliminates the single biggest adoption blocker for real-time applications.

## Status

Placeholder — awaiting implementation.
