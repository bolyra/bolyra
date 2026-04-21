# Conformance test vectors with multi-chain coverage

## Abstract

Produce 60+ JSON test vectors organized by circuit (HumanUniqueness, AgentPolicy, Delegation) covering: valid proofs, expired credentials, revoked identities, stale roots (both human and agent), scope subset violations, cumulative bit encoding violations (bit 4 without bits 2+3), delegation chain at depths 1/2/3/4 (4 must fail), phantom delegatee rejection, nonce replay, and cross-chain root sync scenarios. Each vector includes input signals, expected public outputs, and expected pass/fail status. Ship as a standalone JSON file with a JSON Schema so other implementations can validate their parser.

## Normative Requirements

Implementations MUST ...
