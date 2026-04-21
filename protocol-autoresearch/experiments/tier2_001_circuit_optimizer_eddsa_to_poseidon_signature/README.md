# Replace EdDSA verification with Poseidon-based commitment binding in AgentPolicy

EdDSA verification in AgentPolicy costs ~30k constraints (60%+ of the circuit budget). The operator signature proves the operator authorized the credential, but this can be achieved more cheaply: the operator signs off-chain (verified at enrollment time on-chain), and the circuit only needs to prove knowledge of the preimage to the credential commitment that is already in the Merkle tree. Remove the in-circuit EdDSA verify, save ~30k constraints, cutting proving time roughly in half. The security model shifts to: Merkle inclusion proves the credential was operator-approved at enrollment. Deliverable: simplified AgentPolicy.circom (~20k constraints), updated test vectors, benchmarks showing proving time reduction.

## Status

Placeholder — awaiting implementation.
