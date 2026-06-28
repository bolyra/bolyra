# Experiment: Nullifier Domain Separation

**ID:** `formal_verifier_nullifier_domain_separation`  
**Persona:** Formal Verifier  
**Dimension:** Standards  
**Priority:** Medium  

## Summary

Adds domain separation tags to all Poseidon nullifier derivations across the
three Bolyra identity protocol circuits (HumanUniqueness, AgentPolicy,
Delegation). This prevents cross-circuit nullifier collisions even when
input values coincide across circuits.

## Problem

Prior to this change, all three circuits computed nullifiers using
`Poseidon(a, b)` (arity 2) with no domain separator. If a `credentialCommitment`
happened to equal a `scope` value and a `sessionNonce` equaled a `secret`,
cross-circuit nullifier collisions were possible.

## Solution

Prepend a circuit-specific domain tag as the first Poseidon input:

| Circuit          | Tag | Nullifier Construction                                    | Arity |
|------------------|-----|-----------------------------------------------------------|-------|
| HumanUniqueness  | 1   | `Poseidon₃(1, scope, secret)`                              | 3     |
| AgentPolicy      | 2   | `Poseidon₃(2, agentSecret, policyScope)`                   | 3     |
| Delegation       | 3   | `Poseidon₄(3, delegatorSecret, delegateeCredComm, scope)`  | 4     |

This follows IETF RFC 9380 (hash-to-curve) domain separation conventions.

## Artifacts

### Circuits
- `circuits/src/HumanUniqueness.circom` — `DOMAIN_HUMAN = 1`, Poseidon₃ nullifier
- `circuits/src/AgentPolicy.circom` — `DOMAIN_AGENT = 2`, Poseidon₃ nullifier
- `circuits/src/Delegation.circom` — `DOMAIN_DELEG = 3`, Poseidon₄ nullifier

### Tests
- `circuits/test/nullifier-domain-separation.test.js` — Mocha regression tests
  - Reference Poseidon computation with pairwise distinctness assertions
  - Worst-case scenario: all raw values equal
  - v1.x vs v2.0 nullifier divergence
  - Exhaustive 100-iteration collision sweep
  - Poseidon arity separation verification

### Specifications
- `spec/draft-bolyra-mutual-zkp-auth-01.md` — Section 4: nullifier derivation
  with domain tag registry table and RFC 9380 rationale
- `circuits/FORMAL-PROPERTIES.md` — Property P-DS-1: cross-circuit collision
  resistance with full proof

### SDK
- `sdk/src/nullifier.ts` — Domain-separated nullifier helper functions with
  frozen tag constants matching circuit definitions

### Documentation
- `docs/security-model.md` — Section 2: nullifier domain separation guarantees,
  tag registry, and design rationale

## Usage

### Run tests
```bash
# Fast (witness generation only)
npm run test:circuits:fast

# Full proof (Groth16 + PLONK)
npm run test:circuits:slow

# Just the domain separation tests
npx mocha circuits/test/nullifier-domain-separation.test.js --timeout 120000
```

### Recompile circuits after changes
```bash
npm run compile:circuits
```

### Regenerate trusted setup (required after circuit changes)
```bash
# AgentPolicy and Delegation use project-specific .zkey from pot16.ptau
# HumanUniqueness reuses Semaphore v4 ceremony — .zkey must also be
# regenerated from the new .r1cs
cd circuits && node scripts/compile.js
```

### SDK usage
```typescript
import {
  computeHumanNullifier,
  computeAgentNullifier,
  computeDelegationNullifier,
  HUMAN_NULLIFIER_DOMAIN,
  AGENT_NULLIFIER_DOMAIN,
  DELEGATION_NULLIFIER_DOMAIN,
} from "@bolyra/sdk";

const humanNull = computeHumanNullifier(scope, secret);
const agentNull = computeAgentNullifier(agentSecret, policyScope);
const delegNull = computeDelegationNullifier(delegatorSecret, delegateeCred, scope);
```

## Constraint Budget

| Circuit          | Added Constraints | Total Estimate | Headroom (of 2^16) |
|------------------|-------------------|----------------|---------------------|
| HumanUniqueness  | ~101              | ~40,601        | ~24,935 (38%)       |
| AgentPolicy      | ~101              | ~40,859        | ~24,677 (38%)       |
| Delegation       | ~201              | ~41,051        | ~24,485 (37%)       |

All circuits remain well within the 2^16 (65,536) constraint ceiling.

## Dependencies

- circomlib (Poseidon template supports arbitrary input arity)
- circomlibjs (JS reference implementation for tests)
- pot16.ptau (2^16 constraints — sufficient after +3 constraints total)
- poseidon-lite (SDK nullifier computation)

## Breaking Changes

- **Nullifier values change**: All nullifier outputs differ from v1.x.
  On-chain nullifier registries must be reset or migrated on testnet.
- **Trusted setup invalidated**: All `.zkey` files must be regenerated.
- **Solidity verifiers**: Must be regenerated from new `vkey.json` files.

## References

- IETF RFC 9380: Hashing to Elliptic Curves (domain separation conventions)
- Grassi et al., "Poseidon: A New Hash Function for ZKP Systems" (USENIX 2021)
- `circuits/FORMAL-PROPERTIES.md` — Property P-DS-1
- Prior experiment: `tier2_004_formal_verifier_nullifier_collision_independence`
