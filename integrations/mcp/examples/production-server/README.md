# Production Server Example

Dual-mode MCP server that demonstrates production-shaped Bolyra auth:
credential lookup, nonce replay protection, Merkle root validation,
and per-tool permission policy.

## Modes

- `--dev` -- instant mock proofs, no circuit artifacts needed
- `--production` -- real ZKP proving and verification (requires compiled circuits)

## Quick start

```bash
npm install
npm run demo:dev
```

Expected output: list_files success, read_file success, write_file denied.

## Production run

```bash
BOLYRA_CIRCUIT_DIR=../../../../circuits/build npm run demo:production
```

Requires compiled circuit artifacts (`npm run compile:circuits` from repo root).

## What's real

- **Credential lookup** -- resolveCredential maps commitment to AgentCredential (`--production` only; `--dev` bypasses)
- **Nonce replay protection** -- MemoryNonceStore rejects replayed proof bundles (`--production` only; `--dev` bypasses)
- **Proof-to-credential binding** -- verifier checks proof matches resolved credential
- **Root validation** -- validateRoots callback (mock: accepts all)
- **Tool permission gating** -- per-tool permission bitmask enforcement (both modes)

## What's mocked

- Credential DB (in-memory Map, not Postgres)
- Root validator (accepts all roots, not on-chain check)
- Nonce store (in-memory Map, not Redis)

## Going to real production

1. **Credential store** -- swap InMemoryCredentialStore for Postgres/DynamoDB
2. **Root validator** -- use ethers.js to call IdentityRegistry on-chain
3. **Nonce store** -- implement NonceStore against Redis with TTL
4. **Monitoring** -- add structured logging, metrics on auth failures
5. **TLS** -- if using HTTP transport, terminate TLS at the load balancer
