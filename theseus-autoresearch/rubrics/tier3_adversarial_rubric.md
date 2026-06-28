# Tier 3 — Adversarial Rubric

Every proposal that survives Tier 2 validation must withstand 5 attack axes. A proposal that cannot defend against any single axis is demoted.

## Attack Axes

### 1. "Theseus Builds It Themselves"

**Challenge:** Can Theseus's 1-2 engineers replicate this capability without ZKP expertise in < 3 months?

**Defense must address:**
- What specific ZKP expertise is required? (Circom circuit design, trusted setup ceremonies, proof system selection)
- How long did it take Bolyra to build the equivalent? (Cite actual development time)
- Is there an open-source ZKP library they could use instead of Bolyra? (e.g., circomlib, snarkjs directly)
- Would a simpler non-ZKP approach get them 80% of the value?

**Kill signal:** If the capability can be replicated with standard Solidity + OpenZeppelin in 2 weeks, DROP.

### 2. "Standard Crypto Suffices"

**Challenge:** EdDSA signatures + Merkle trees + on-chain ACLs can provide authentication and authorization without ZKP overhead. Why isn't that enough?

**Defense must address:**
- What specific property does ZKP provide that standard crypto cannot? (privacy, succinctness, composability)
- What is the concrete cost of NOT having that property? (data leak, gas cost, trust assumption)
- Is the ZKP overhead (proof generation time, verification gas, circuit complexity) justified by the marginal benefit?

**Kill signal:** If the only advantage is "privacy" but the data being hidden has no economic or security value, DROP.

### 3. "No Agent Actually Needs This"

**Challenge:** Is this capability operationally needed by agents in the first 12 months of Theseus, or is it a theoretical concern?

**Defense must address:**
- What is the first concrete agent use case that requires this? (Name the agent type, its function, and why it fails without this capability)
- How many agents need this at launch vs at 1,000 agents vs at 100,000?
- Is this a prerequisite for other capabilities, or an isolated feature?

**Kill signal:** If no specific agent use case can be named, or the need only arises at >10,000 agents, DROP.

### 4. "Integration Complexity vs Value"

**Challenge:** Bolyra uses Circom circuits compiled to R1CS, Groth16/PLONK proving, and Base Sepolia contracts. If Theseus runs a custom L1 (possibly non-EVM), integration friction may exceed the value.

**Defense must address:**
- What is the verification-side integration work? (Deploy Solidity verifier? Implement custom verifier in Theseus VM?)
- What is the proving-side integration work? (Agent runs snarkjs/rapidsnark? Bolyra hosts a proving service?)
- Is the proof format chain-agnostic, or does it need modification for Theseus?
- What's the gas/compute cost of on-chain proof verification on Theseus?

**Kill signal:** If integration requires Theseus to adopt EVM or implement a custom Groth16 verifier from scratch, and the value doesn't justify that work, DROP.

### 5. "Single-Partner Dependency"

**Challenge:** If Theseus fails (runs out of funding, pivots, never launches), is the work Bolyra does for this integration wasted?

**Defense must address:**
- Is the capability generalizable to other agent-native chains or platforms?
- Does the work produce reusable primitives (circuits, contracts, SDK modules) that serve Bolyra's broader roadmap?
- Would building this for Theseus accelerate Bolyra's protocol even if Theseus disappears?

**Kill signal:** If the work is entirely Theseus-specific with no reuse value, CONSIDER at best (never PROMOTE).

## Scoring Impact

- **Survives all 5 axes:** Score unchanged, proceed to final ranking
- **Survives 4/5:** Deduct 5 points from the weakest dimension
- **Survives 3/5:** Demote from PROMOTE to CONSIDER
- **Survives 2 or fewer:** DROP regardless of raw score
