# SD-JWT-based session token for off-chain verifiers

## Abstract

On-chain verification is expensive and unnecessary for many use cases (API gateways, MCP servers). Define a standardized SD-JWT (IETF draft-ietf-oauth-selective-disclosure-jwt) session token that an on-chain verifier mints after a successful handshake: claims include nullifierHash, scopeCommitment, agentMerkleRoot, and exp. Off-chain verifiers check the JWT signature against the registry's signing key without touching the chain. This bridges Bolyra into the existing OAuth/OIDC ecosystem. Deliver: JWT claim set spec, issuance flow in IdentityRegistry (or a companion Relayer contract), and SDK method verifySessionToken().

## Normative Requirements

Implementations MUST ...
