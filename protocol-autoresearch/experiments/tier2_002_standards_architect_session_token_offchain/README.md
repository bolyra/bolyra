# Define off-chain session token format for verified handshakes

After a successful on-chain handshake verification, there is no standardized bearer token format for the resulting session. Define a compact JWT-like session token (JWS with EdDSA over BabyJubjub) that encodes the verified nullifierHash, scopeCommitment, sessionNonce, and expiry. This enables off-chain relying parties to accept Bolyra auth results without querying the chain for every API call. Include IANA media type registration for application/bolyra-session+jwt and a COSE equivalent for constrained environments.

## Status

Placeholder — awaiting implementation.
