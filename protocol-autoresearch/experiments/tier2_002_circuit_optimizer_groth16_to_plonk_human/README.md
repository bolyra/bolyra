# Migrate HumanUniqueness from Groth16 to PLONK

HumanUniqueness currently uses Groth16 requiring a trusted ceremony (reusing Semaphore v4's depth-20 ceremony). Migrating to PLONK (matching AgentPolicy and Delegation) eliminates ceremony trust assumptions, unifies the proving stack to a single backend, and simplifies the IdentityRegistry contract by removing the separate IGroth16Verifier interface. The circuit is small (~15k constraints for BabyPbk + Poseidon + Merkle), well within PLONK's efficiency range. Deliverable: recompiled HumanUniqueness circuit with PLONK proving key, updated HumanVerifier.sol, and unified verifier interface in IdentityRegistry.

## Status

Placeholder — awaiting implementation.
