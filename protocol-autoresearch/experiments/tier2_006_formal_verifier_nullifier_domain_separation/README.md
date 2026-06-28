# Add domain separation tags to all nullifier hash computations

HumanUniqueness computes nullifier as Poseidon2(scope, secret) and AgentPolicy computes it as Poseidon2(secret, sessionNonce). Both use Poseidon2 with no domain separator, meaning a collision is possible if an agent's (secret, sessionNonce) pair equals a human's (scope, secret) pair — the nullifier spaces overlap. Prepend a unique domain tag constant (e.g., 0xHUMAN, 0xAGENT, 0xDELEG) as the first Poseidon input to each nullifier computation across all three circuits. This is a standard formal verification finding: hash function domain separation prevents cross-protocol nullifier confusion.

## Status

Placeholder — awaiting implementation.
