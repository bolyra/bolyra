# Self-describing proof envelope with content-type and version negotiation

Currently proofs are bare JSON arrays of bigints with implicit positional semantics — integrators must know that `publicSignals[0]` is `humanMerkleRoot` and `publicSignals[4]` is `nonceBinding`. Define a `BolyraEnvelope` codec (msgpack or CBOR with JSON fallback) that wraps proofs with `{ version: '0.2', circuit: 'HumanUniqueness', provingSystem: 'groth16', publicSignals: { humanMerkleRoot, nullifierHash, nonceBinding, ... }, proof: {...} }`. Add `BolyraEnvelope.encode()` / `BolyraEnvelope.decode()` to both TS and Python SDKs. This eliminates the `publicSignals[5]` positional indexing that caused the chainId mismatch bug in the cross-chain experiment.

## Status

Placeholder — awaiting implementation.
