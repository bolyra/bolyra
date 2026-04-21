# Migrate HumanUniqueness from Groth16 to PLONK for unified proving

HumanUniqueness uses Groth16 (requiring trusted setup ceremony reuse from Semaphore v4 depth-20), while AgentPolicy and Delegation use PLONK. This forces SDK consumers to bundle two different proving systems, increasing WASM bundle size by ~2MB and doubling key management complexity. Migrate HumanUniqueness to PLONK with the same universal SRS. The circuit is small (~15k constraints with BabyPbk + Merkle + Poseidon), well within PLONK's sweet spot. Unifies the verifier interface, halves client-side code, and removes the ceremony dependency.

## Status

Placeholder — awaiting implementation.
