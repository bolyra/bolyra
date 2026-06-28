# Experiment: Self-describing proof envelope with named public signals

**ID:** `sdk_designer_proof_envelope_codec`  
**Dimension:** adoption  
**Priority:** high  
**Persona:** sdk_designer  

## Problem

Proofs are currently bare `{ proof, publicSignals: bigint[] }` with positional
semantics — `publicSignals[0]` vs `publicSignals[4]` is a constant source of
integration bugs. Integrators must memorise or look up the signal order for
each circuit, and off-by-one errors silently produce wrong verifications.

## Solution

Ship a `BolyraEnvelope` type with `encode()`/`decode()` that wraps proofs in:

```jsonc
{
  "version": "1.0.0",
  "circuit": "HumanUniqueness",
  "provingSystem": "groth16",
  "signals": {
    "humanMerkleRoot": "789...",
    "nullifierHash": "123...",
    "nonceBinding": "456...",
    "externalNullifier": "012...",
    "sessionNonce": "345..."
  },
  "proof": { /* snarkjs passthrough */ }
}
```

Includes a `fromRaw(circuit, rawSignals)` migration helper. Published in both
TS (`@bolyra/sdk`) and Python (`bolyra`) SDKs.

## Artifacts

| File | Description |
|---|---|
| `spec/proof-envelope-v1.md` | Wire format specification |
| `sdk/src/signals.ts` | Per-circuit signal name maps |
| `sdk/src/envelope.ts` | `BolyraEnvelope` type, `encode()`, `decode()`, `fromRaw()` |
| `sdk/src/index.ts` | Re-exports envelope API |
| `sdk-python/bolyra/signals.py` | Python signal maps (mirrors TS) |
| `sdk-python/bolyra/envelope.py` | Python `BolyraEnvelope` dataclass with encode/decode |
| `sdk/test/envelope.test.ts` | TS unit tests (Mocha/Chai) |
| `sdk-python/tests/test_envelope.py` | Python unit tests (pytest) |
| `sdk/QUICKSTART.md` | Migration guide with before/after examples |

## Signal Maps

Derived from circuit `signal output` and `component main {public [...]}` declarations:

### HumanUniqueness (5 signals)

| Index | Name | Type |
|---|---|---|
| 0 | `nullifierHash` | output |
| 1 | `nonceBinding` | output |
| 2 | `humanMerkleRoot` | public input |
| 3 | `externalNullifier` | public input |
| 4 | `sessionNonce` | public input |

### AgentPolicy (6 signals)

| Index | Name | Type |
|---|---|---|
| 0 | `credentialHash` | output |
| 1 | `nonceBinding` | output |
| 2 | `agentMerkleRoot` | public input |
| 3 | `currentTimestamp` | public input |
| 4 | `requiredPermissions` | public input |
| 5 | `sessionNonce` | public input |

### Delegation (6 signals)

| Index | Name | Type |
|---|---|---|
| 0 | `delegationHash` | output |
| 1 | `narrowedPermissions` | output |
| 2 | `nonceBinding` | output |
| 3 | `delegationMerkleRoot` | public input |
| 4 | `currentTimestamp` | public input |
| 5 | `sessionNonce` | public input |

## Usage

### TypeScript

```ts
import { fromRaw, decode } from '@bolyra/sdk';

// Wrap raw snarkjs output:
const envelope = fromRaw('HumanUniqueness', 'groth16', proof, publicSignals);
console.log(envelope.signals.humanMerkleRoot); // named access

// Convert back for verification:
const { proof: p, publicSignals: s } = decode(envelope);
await snarkjs.groth16.verify(vkey, s, p);
```

### Python

```python
from bolyra.envelope import from_raw, decode

envelope = from_raw('HumanUniqueness', 'groth16', proof, public_signals)
print(envelope.signals['humanMerkleRoot'])  # named access

result = decode(envelope)
verify(result['proof'], result['publicSignals'])
```

## Running Tests

```bash
# TypeScript
cd sdk && npx mocha test/envelope.test.ts

# Python
cd sdk-python && pytest tests/test_envelope.py -v
```
