# Standardize off-chain session token format post-handshake

After a successful on-chain handshake verification, there is no standard for the session artifact the verifier issues to the prover. Define a compact session token (JWT or CWT profile) that encodes: verified nullifier hashes, scope commitment, session nonce, chain ID, block number of verification, and expiry. Specify the signing algorithm (EdDSA or ES256), required claims, and validation rules. This bridges the gap between on-chain proof verification and off-chain application-layer authorization, which is the actual integration point for LangChain/CrewAI/MCP consumers.

## Status

Placeholder — awaiting implementation.
