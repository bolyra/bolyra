# Experiment: scope-blinding-salt

**ID:** `standards_architect_scope_blinding_salt`  
**Dimension:** correctness  
**Priority:** medium  
**Verdict:** consider

## Problem

`scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)` uses only
two inputs. Since `permissionBitmask` is 8 meaningful bits (256 values), an
observer can brute-force all possible commitments against a known
`credentialCommitment` and recover the exact permission set in < 1ms.

## Solution

Add a random blinding salt as a third Poseidon input:

```
scopeCommitment = Poseidon(permissionBitmask, credentialCommitment, blindingSalt)
```

The `blindingSalt` is a private circuit input generated via CSPRNG (254-bit).
The commitment remains public; the salt is never revealed.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuits/src/AgentPolicy.circom` | circuit | 3-input Poseidon for scopeCommitment |
| `circuits/src/Delegation.circom` | circuit | Per-hop blindingSalt threading |
| `contracts/src/BolyraVerifier.sol` | contract | Placeholder for regenerated verifier |
| `sdk/src/agent.ts` | SDK | CSPRNG salt generation + witness passing |
| `sdk/src/types.ts` | SDK | `blindingSalt: bigint` on AgentCredential (schema v3) |
| `circuits/test/AgentPolicy.test.ts` | test | Salt distinctness + brute-force resistance |
| `circuits/test/Delegation.test.ts` | test | Per-hop salt + scope narrowing |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | spec | Section 9: enumeration attack + salt requirements |
| `circuits/FORMAL-PROPERTIES.md` | docs | scopeCommitment binding property |

## Usage

### Compile circuits

```bash
npm run compile:circuits
```

### Run tests (fast — witness only)

```bash
npm run test:circuits:fast
```

### Run tests (slow — full Groth16/PLONK proofs)

```bash
npm run test:circuits:slow
```

### Re-run trusted setup after circuit change

```bash
# Generate new R1CS
circom circuits/src/AgentPolicy.circom --r1cs --wasm -o circuits/build/

# Groth16 setup
snarkjs groth16 setup circuits/build/AgentPolicy.r1cs circuits/build/pot16.ptau \
  circuits/build/AgentPolicy_0000.zkey
snarkjs zkey contribute circuits/build/AgentPolicy_0000.zkey \
  circuits/build/AgentPolicy_final.zkey --name="scope-blinding-salt" -v

# Export verification key + Solidity verifier
snarkjs zkey export verificationkey circuits/build/AgentPolicy_final.zkey \
  circuits/build/AgentPolicy_vkey.json
snarkjs zkey export solidityverifier circuits/build/AgentPolicy_final.zkey \
  contracts/src/BolyraVerifier.sol
```

Repeat for Delegation circuit.

### SDK usage

```typescript
import { createAgentCredential, proveHandshake } from '@bolyra/sdk';

// blindingSalt is auto-generated (CSPRNG, 254-bit)
const cred = await createAgentCredential(modelHash, privKey, 0b00000111, expiry);
console.log(cred.blindingSalt); // unique per credential

const result = await proveHandshake(cred, sessionNonce, timestamp);
// result.scopeCommitment is blinded — cannot be brute-forced
```

## Breaking Changes

- **AgentCredential schema v3**: adds required `blindingSalt: bigint` field
- **Circuit witness**: `blindingSalt` is now a required private input
- **Trusted setup**: must be re-run for AgentPolicy and Delegation circuits
- **Solidity verifier**: must be regenerated from new vkey

## Constraint Impact

| Circuit | Before | After | Delta |
|---------|--------|-------|-------|
| AgentPolicy | ~250 | ~280 | +30 |
| Delegation | ~200 | ~260 | +60 (two 3-input Poseidons) |

Proving time impact: < 5% increase (Groth16 on rapidsnark).

## Security Analysis

See `spec/draft-bolyra-mutual-zkp-auth-01.md` §9.1 for the full analysis.

**Before (vulnerable):**
- Adversary knows `credentialCommitment` (public output)
- Tries all 256 bitmask values: `Poseidon(trial, credCommitment)`
- Matches in < 1ms → full permission set recovered

**After (mitigated):**
- `scopeCommitment = Poseidon(bitmask, credCommitment, blindingSalt)`
- Search space: 256 × 2^254 ≈ 2^262
- Brute-force is computationally infeasible
