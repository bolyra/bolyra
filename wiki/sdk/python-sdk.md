---
title: "bolyra Python SDK"
visibility: public
sources:
  - sdk-python/README.md
  - sdk-python/pyproject.toml
  - sdk-python/bolyra/__init__.py
  - sdk-python/bolyra/types.py
  - sdk-python/bolyra/_bridge.py
  - sdk-python/bolyra/identity.py
  - sdk-python/bolyra/handshake.py
  - sdk-python/bolyra/delegation.py
  - sdk-python/bolyra/errors.py
  - sdk-python/bolyra/envelope.py
  - sdk-python/bolyra/sd_jwt.py
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [sdk, python, pypi, bridge]
---

The `bolyra` Python package (v0.5.0 on PyPI, `__version__` = 0.4.0 in code) provides Python-native types, validation, and error handling for Bolyra, plus a subprocess bridge to the Node.js `@bolyra/sdk` for ZK proof generation.

## Overview

- **Package:** `bolyra` on PyPI
- **Python:** >=3.10
- **License:** Apache-2.0
- **Build:** Hatchling
- **Runtime dependency:** `PyJWT[crypto]>=2.8.0` (for SD-JWT support)
- **Proof generation dependency:** Node.js 18+ with `@bolyra/sdk` installed

Install:

```bash
pip install bolyra
```

For proof generation, also install the Node.js SDK:

```bash
npm install @bolyra/sdk
```

## Key Concepts

**Pure Python layer.** Types (`HumanIdentity`, `AgentCredential`, `Permission`, etc.), validation functions (`permissions_to_bitmask`, `validate_cumulative_bit_encoding`), and error classes are implemented in pure Python with zero external dependencies beyond PyJWT. These mirror the TypeScript SDK exactly.

**Subprocess bridge.** Any operation requiring ZK proof generation (handshake proving, delegation) shells out to Node.js via `node -e`. The bridge module (`bolyra/_bridge.py`) handles:
- Resolving the Node.js SDK path (config, env var `BOLYRA_NODE_SDK_PATH`, or sibling `../sdk`)
- Running scripts with a 120s timeout
- Parsing JSON output and surfacing typed `BolyraError` subclasses from stderr

**SD-JWT support.** The Python SDK includes native SD-JWT (Selective Disclosure JWT) functions: `sd_jwt_allow`, `sd_jwt_present`, `sd_jwt_verify`, and `generate_ed25519_keypair`. These are pure Python (via PyJWT).

## How It Works

```python
from bolyra import Permission, permissions_to_bitmask, validate_cumulative_bit_encoding

# Pure Python -- no Node.js needed
bitmask = permissions_to_bitmask([
    Permission.READ_DATA,
    Permission.WRITE_DATA,
    Permission.FINANCIAL_SMALL,
])
validate_cumulative_bit_encoding(bitmask)  # raises on invalid encoding

# For proof generation -- requires Node.js + @bolyra/sdk
from bolyra import prove_handshake, verify_handshake
result = prove_handshake(human, agent)  # spawns node subprocess
```

The bridge resolves the Node.js SDK in this order:
1. `config.node_sdk_path` (explicit)
2. `BOLYRA_NODE_SDK_PATH` environment variable
3. `../sdk` relative to the `sdk-python/` package root (monorepo default)

## Public API

### Types
`HumanIdentity`, `AgentCredential`, `HandshakeResult`, `DelegationResult`, `DelegateeMerkleProof`, `Permission`, `BolyraConfig`, `Point`, `EdDSASignature`

### Functions
- `create_human_identity(secret)` -- create EdDSA identity
- `create_agent_credential(model_hash, operator_key, permissions, expiry)` -- create signed credential
- `create_dev_identities()` -- fixed-seed test identities
- `permissions_to_bitmask(permissions)` -- convert permission list to bitmask
- `validate_cumulative_bit_encoding(bitmask)` -- validate cumulative rules
- `prove_handshake(human, agent, ...)` -- generate mutual ZKP (via Node.js bridge)
- `verify_handshake(human_proof, agent_proof, nonce)` -- verify handshake (via Node.js bridge)
- `delegate(input)` -- generate delegation proof (via Node.js bridge)
- `verify_delegation(proof, ...)` -- verify delegation proof (via Node.js bridge)
- `sd_jwt_allow(...)`, `sd_jwt_present(...)`, `sd_jwt_verify(...)` -- SD-JWT operations (pure Python)
- `generate_ed25519_keypair()` -- generate Ed25519 key pair for SD-JWT

### Errors
All errors extend `BolyraError` with a `.code` property matching the TypeScript SDK: `ProofGenerationError`, `VerificationError`, `InvalidPermissionError`, `ExpiredCredentialError`, `ScopeEscalationError`, `StaleProofError`, `InvalidSecretError`, `CircuitArtifactNotFoundError`, `MerkleTreeError`, `ConfigurationError`.

## Current Status

- Pure types and validation: stable
- Subprocess bridge: stable (120s timeout, typed error propagation)
- SD-JWT: stable
- Dev identities: stable

The Python SDK intentionally does not reimplement ZK proving in Python. snarkjs is JavaScript-only; any new feature needing proof generation should go through the subprocess bridge.

## See Also

- [TypeScript SDK](./typescript-sdk.md) -- the primary SDK
- [Quickstart](./quickstart.md) -- getting started guide
- [API Reference](./api-reference.md) -- complete TS API reference
- `sdk-python/README.md` -- canonical README
