# Off-chain JWT session token after on-chain handshake verification

After a successful on-chain `verifyMutualHandshake`, issue a signed JWT session token (HS256 or ES256) that encodes the verified nullifiers, scope commitment, and an expiry window (e.g. 15 minutes). Subsequent tool calls within the session present this JWT instead of re-proving on-chain. This eliminates the per-call gas cost that makes Bolyra impractical for LangChain agent loops that may invoke 20-50 tools per session. The JWT includes a `bolyra_session_nonce` claim tied to the on-chain nonce, so replay is still prevented. Implement as a `SessionTokenIssuer` in the TS SDK and a `verify_session_token()` helper in the Python SDK.

## Status

Placeholder — awaiting implementation.
