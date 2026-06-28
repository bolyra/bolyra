# Bolyra Conformance Test Vectors

Machine-readable test vectors for third-party implementations of the Bolyra identity protocol.

## Overview

This directory contains frozen JSON test vectors covering:

| Vector | Circuit | Expected |
|--------|---------|----------|
| `valid_handshake.json` | HumanUniqueness + AgentPolicy | pass |
| `expired_agent_credential.json` | AgentPolicy | fail |
| `revoked_human_identity.json` | HumanUniqueness | fail |
| `stale_merkle_root.json` | HumanUniqueness | fail |
| `scope_subset_violation.json` | Delegation | fail |
| `cumulative_bit_violation.json` | SDK validation | fail |
| `delegation_depth_1.json` | Delegation | pass |
| `delegation_depth_2.json` | Delegation (×2) | pass |
| `delegation_depth_3.json` | Delegation (×3) | pass |
| `nonce_replay.json` | HumanUniqueness + AgentPolicy | fail |

## Schema

All vector files conform to `schema.json`. Each vector contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique vector identifier |
| `description` | string | Human-readable purpose |
| `circuit` | string | Circuit name: `HumanUniqueness`, `AgentPolicy`, `Delegation`, or `SDK` |
| `input_witnesses` | object | Full witness input (private + public signals) |
| `public_signals` | string[] | Expected public signal values (decimal strings) |
| `expected_result` | `"pass"` \| `"fail"` | Whether witness generation should succeed |
| `failure_reason` | string? | Required when `expected_result` is `"fail"` |
| `meta` | object? | Optional metadata (version, generation date, etc.) |

For multi-circuit vectors (handshake, delegation chains), the top-level structure uses a `steps` array, where each step contains the fields above.

## Conformance Levels

| Level | Name | What it proves |
|-------|------|----------------|
| **L1** | Schema-valid | Vector file passes JSON Schema validation via `validate_schema.js` |
| **L2** | Witness-match | Witness generation succeeds/fails as expected; public signals match |
| **L3** | Full-proof-match | Full Groth16/PLONK proof generation and verification succeeds/fails as expected |

A conformant implementation MUST pass L1 and L2. L3 is RECOMMENDED for production deployments.

## Running the Suite

### Prerequisites

- Node.js 18+
- `snarkjs` and `circom_tester` (dev dependencies in root `package.json`)
- Compiled circuit artifacts in `circuits/build/`

### Quick Start

```bash
# Validate schema only (L1)
node spec/test-vectors/scripts/validate_schema.js

# Full conformance check (L1 + L2)
npm run test:vectors

# Generate/refresh frozen vectors from circuit tests (requires FULL_PROOF=1)
FULL_PROOF=1 node spec/test-vectors/scripts/extract_vectors.js
```

### npm Scripts

```bash
npm run test:vectors          # validate_schema.js && validate_vectors.js
npm run test:vectors:extract  # FULL_PROOF=1 extract_vectors.js (slow, ~2min/vector)
```

### Third-Party SDK Integration

To run these vectors against your own SDK:

1. Parse each `.json` file in `spec/test-vectors/`
2. For each vector (or each step in multi-step vectors):
   - Feed `input_witnesses` to your witness generator for the named `circuit`
   - If `expected_result` is `"pass"`: assert witness generation succeeds and `public_signals` match
   - If `expected_result` is `"fail"`: assert witness generation throws or proof verification fails
3. For `circuit: "SDK"` vectors, run the named SDK validation function instead of a circuit

## Circuit Signal Reference

### HumanUniqueness

**Public inputs:** `identityTreeRoot`, `nullifierHash`, `scope`

**Private inputs:** `secret`, `identityNonce`, `merklePathElements[20]`, `merklePathIndices[20]`

### AgentPolicy

**Public inputs:** `agentTreeRoot`, `nullifierHash`, `currentTimestamp`, `expiryTimestamp`

**Private inputs:** `agentSecret`, `agentNonce`, `policyScope`, `merklePathElements[20]`, `merklePathIndices[20]`

### Delegation

**Public inputs:** `agentTreeRoot`, `scopeCommitment`, `nullifierHash`

**Private inputs:** `delegatorSecret`, `delegatorNonce`, `delegateeCredCommitment`, `scope`, `merklePathElements[20]`, `merklePathIndices[20]`

## Versioning

Vector files include a `meta.version` field. When circuit semantics change (e.g., domain-separated nullifiers in v2.0.0), vectors MUST be regenerated via `extract_vectors.js` and the version bumped.

Current version: **1.0.0** (circuits v2.0.0 — domain-separated nullifiers)
