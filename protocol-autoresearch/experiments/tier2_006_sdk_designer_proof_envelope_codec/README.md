# Self-Describing Proof Envelope with Named Public Signals

## Problem

Proofs are currently bare `{ proof, publicSignals: bigint[] }` with positional
semantics — `publicSignals[0]` vs `publicSignals[4]` is a constant source of
integration bugs. When circuit signal layouts change, every consumer breaks
silently.

## Solution

A `BolyraEnvelope` type with `encode()`/`decode()` that wraps proofs in a
self-describing JSON envelope:

```json
{
  "version": "1.0.0",
  "circuit": "HumanUniqueness",
  "provingSystem": "groth16",
  "signals": {
    "humanMerkleRoot": "19014...",
    "nullifierHash": "86459...",
    "nonceBinding": "20938..."
  },
  "proof": { ... }
}
```

## Usage

### TypeScript

```typescript
import { encode, decode, fromRaw } from '@bolyra/sdk';

// Encode raw snarkjs output into a named envelope
const envelope = encode('HumanUniqueness', 'groth16', proof, publicSignals);
console.log(envelope.signals.humanMerkleRoot); // named access!

// Decode back to positional array for verification
const decoded = decode(JSON.parse(jsonString));
const orderedSignals = decoded.publicSignals; // bigint[]

// Migration helper (alias for encode)
const env = fromRaw('HumanUniqueness', 'groth16', proof, publicSignals);
```

### Python

```python
from bolyra.envelope import encode, decode, from_raw

# Encode
env = encode('HumanUniqueness', 'groth16', proof_dict, signal_list)
print(env.signals['humanMerkleRoot'])  # named access

# Serialize to JSON-compatible dict
wire = env.to_dict()

# Decode
decoded = decode(wire)
ordered = decoded.to_public_signals()  # list[int]
```

## Supported Circuits

| Circuit           | Signals | Proving Systems |
|-------------------|---------|-----------------|
| HumanUniqueness   | 3       | groth16         |
| AgentPolicy       | 4       | groth16, plonk  |
| Delegation        | 4       | groth16, plonk  |

## Error Handling

Both SDKs throw typed errors:

- `EnvelopeVersionError` — unsupported major version
- `UnknownCircuitError` — unrecognized circuit name
- `SignalCountMismatch` — wrong number of signals for the circuit
- `InvalidProvingSystemError` — proving system not valid for circuit

## Artifacts

| File | Description |
|------|-------------|
| `spec/proof-envelope-v1.md` | Wire format specification |
| `sdk/src/circuits/signal-maps.ts` | Authoritative signal name arrays |
| `sdk/src/envelope.ts` | TS encode/decode/fromRaw |
| `sdk/src/index.ts` | Public API re-exports |
| `sdk-python/bolyra/envelope.py` | Python mirror |
| `sdk/test/envelope.test.ts` | TS test suite |
| `sdk-python/tests/test_envelope.py` | Python test suite |
| `sdk/test/fixtures/envelope-v1-samples.json` | Cross-SDK test fixtures |
