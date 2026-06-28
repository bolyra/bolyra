# Tier 2 — Validation Rubric

Evidence requirements for proposals that pass Tier 1 discovery. Each dimension must be supported by concrete evidence, not just assertion.

## Evidence Requirements by Dimension

### Agent Need

**Required evidence (at least one):**
- Citation from Theseus documentation, codebase, or community discussion showing agents need this capability
- Structural argument from the "no human key path" constraint — demonstrate why this need is inherent to the architecture
- Analogous evidence from another agent-native system (e.g., Fetch.ai, SingularityNET) showing the same need emerged

**Insufficient evidence:**
- "Agents probably need this" without citing any source
- General AI agent trend articles that don't address L1-native agents
- Hypothetical scenarios with no precedent

### ZKP Edge

**Required evidence:**
- Name the specific non-ZKP alternative (e.g., EdDSA + Merkle tree, ACL smart contract, multisig)
- Explain concretely why the non-ZKP alternative fails or is meaningfully worse
- The failure must be structural (privacy leak, O(n) verification, trusted third party) not just "ZKP is cooler"

**Insufficient evidence:**
- "ZKP provides better privacy" without specifying what is being hidden from whom
- Comparing ZKP to no solution at all (strawman)
- Ignoring that standard crypto solves 80% of the problem

### Primitive Readiness

**Required evidence:**
- Name the exact Bolyra circuit, contract function, or SDK method that serves this need
- If new work is required, specify: new circuit (estimate constraints), contract change (which function), SDK surface area
- Provide a realistic timeline in days, accounting for testing and deployment

**Insufficient evidence:**
- "Bolyra's SDK can handle this" without naming the specific function
- Underestimating new circuit development (a new Circom circuit is minimum 3-5 days including testing)
- Ignoring contract deployment and SDK update work

### Partnership Leverage

**Required evidence:**
- Argue why Theseus cannot build this themselves in < 3 months with 1-2 engineers
- Identify the specific expertise gap (ZKP circuit design, trusted setup, Circom proficiency)
- Show that the integration creates value for both sides, not just Bolyra

**Insufficient evidence:**
- "They'd need to learn ZKP" without assessing their team's crypto background
- Assuming Theseus has no identity solution in progress
- Ignoring that Theseus could adopt a competitor (Lit Protocol, Turnkey) instead

## Validation Process

1. For each proposal, check evidence against all 4 dimensions
2. If any dimension lacks required evidence, mark as EVIDENCE_GAP and specify what's needed
3. Proposals with 2+ EVIDENCE_GAP dimensions are demoted to CONSIDER or DROP
4. Proposals that pass all 4 evidence checks proceed to Tier 3 adversarial challenge
