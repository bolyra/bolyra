# Off-chain JWT session token from verified handshake for framework middleware

After a successful on-chain verifyHandshake(), the SDK should emit a signed JWT containing the nullifierHash, scopeCommitment, and sessionNonce with a configurable TTL (default 5 min). Framework middleware (LangChain, CrewAI, AutoGen) can then verify this JWT locally for subsequent tool calls in the same session without re-proving on-chain. This eliminates the biggest adoption blocker: multi-second proof generation on every tool invocation. The JWT issuer key is derived from the agent's operator EdDSA key, so verification stays self-sovereign.

## Status

Placeholder — awaiting implementation.
