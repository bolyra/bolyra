# Off-chain session token format with JWT-compatible envelope

Define a standardized off-chain session token that wraps a verified handshake result into a JWT-compatible envelope (RFC 7519). After on-chain verifyHandshake succeeds, the relayer issues a signed JWT whose claims include humanNullifier, agentNullifier, scopeCommitment, and sessionNonce — enabling stateless verification by downstream services without additional on-chain calls. The token MUST include an `iss` claim bound to the relayer's DID, a `nbf`/`exp` window, and a `bolyra_proof_tx` claim linking back to the on-chain settlement. This bridges the gap between Bolyra's on-chain verification and the HTTP-native auth flows that web services expect.

## Status

Placeholder — awaiting implementation.
