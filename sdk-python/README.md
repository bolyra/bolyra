# bolyra

Python SDK for [Bolyra](https://bolyra.ai) — zero-knowledge identity verification for AI agents.

## Install

```bash
pip install bolyra
```

## Quick Start

```python
from bolyra import Permission, permissions_to_bitmask, validate_cumulative_bit_encoding

# Define agent permissions
bitmask = permissions_to_bitmask([
    Permission.READ_DATA,
    Permission.WRITE_DATA,
    Permission.FINANCIAL_SMALL,
])
print(f"Bitmask: {bitmask}")  # 7

# Validate cumulative encoding
validate_cumulative_bit_encoding(bitmask)  # OK — no exception

# Types for identity and credentials
from bolyra import HumanIdentity, AgentCredential, HandshakeResult
```

## Architecture

The Python SDK provides:
- **Pure Python** types, validation, and error handling (zero dependencies)
- **Subprocess bridge** to the Node.js `@bolyra/sdk` for ZK proof generation (snarkjs is JavaScript-only)

For proof generation and verification, install the Node.js SDK:
```bash
npm install @bolyra/sdk
```

## API

### Types
- `HumanIdentity` — EdDSA identity with secret, public key, and commitment
- `AgentCredential` — AI agent credential with model hash, permissions, expiry
- `HandshakeResult` — Mutual handshake verification result
- `Permission` — 8-bit permission enum with cumulative encoding

### Functions
- `permissions_to_bitmask(permissions)` — Convert permission list to bitmask
- `validate_cumulative_bit_encoding(bitmask)` — Validate cumulative bit rules
- `validate_human_secret(secret)` — Validate secret is within BN254 field
- `validate_agent_expiry(expiry)` — Validate expiry is in the future

### Errors
All errors extend `BolyraError` with a `.code` property matching the TypeScript SDK.

## License

Apache-2.0 — see [LICENSE](../LICENSE).
