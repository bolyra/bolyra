The file write is pending your approval. Here's what this refinement does:

**Single gap closed**: `agentSecret = Poseidon2(operatorSecret, modelHash)` → `agentSecret = Poseidon2(credCommitment, blindingSalt)`

**Key changes across sections (Section 1 preserved verbatim):**

- **§2**: Replaced `agentSecret` private input with `blindingSalt` (client-generated, 256-bit CSPRNG). Added constraint group 3 (`agentSecret = Poseidon2(credCommitment, blindingSalt)`) and constraint group 1 (`Num2Bits(254)` range check). Added explanation of why `credCommitment` replaces `operatorSecret` in the derivation.

- **§3**: Threat model now explicitly grants A the `operatorSecret` (operator = AS case). Added §3.1 with full blindingSalt lifecycle: generation (CSPRNG, AS-excluded), storage (3-tier: HSM > keychain > encrypted file), rotation (voluntary, no on-chain tx), recovery (no AS recovery, optional Shamir), and 5 MUST NOT rules.

- **§4**: Added Hybrid 0 showing that A knowing `credCommitment` is irrelevant when `blindingSalt` is the PRF key. Explicit paragraph on why the old derivation was fatal (Hybrid 1 collapses when operator = AS). Lifecycle-reduction binding paragraph ties the five MUST NOT rules to the uniformity assumption.

- **§6**: +854 constraints (~600 for Poseidon2 derivation, ~254 for range check) → 15,943 total, still < 3s PLONK target.

- **§7**: SECU scenario now explicitly models operator = AS and walks through why `blindingSalt` blocks correlation.
