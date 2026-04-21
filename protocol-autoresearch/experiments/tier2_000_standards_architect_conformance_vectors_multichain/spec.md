# Cross-implementation conformance test vectors

## Abstract

Produce 60+ JSON test vectors organized by circuit (HumanUniqueness, AgentPolicy, Delegation) and by outcome (valid, invalid-stale-root, invalid-revoked, invalid-scope-superset, invalid-expired, invalid-nonce-reuse, invalid-phantom-delegatee). Each vector includes: input witness, expected public signals, expected verification result, and the specific error code from the contract. Vectors cover the root history buffer edge case (root at position 29 vs evicted root at position 30) and the cumulative bit encoding invariant (bit 4 without bits 2+3). These become the canonical interop test suite — any conforming implementation must pass all vectors.

## Normative Requirements

Implementations MUST ...
