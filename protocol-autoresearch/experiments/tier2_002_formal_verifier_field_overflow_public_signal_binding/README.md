# Experiment: Public Signal Field Overflow — Solidity/Circuit Semantic Mismatch

**ID:** `formal_verifier_field_overflow_public_signal_binding`  
**Priority:** Critical  
**Dimension:** Correctness  

## Problem

The `IdentityRegistry` contract accepts public signals as `uint256` and passes
them to snarkjs-generated Groth16/PLONK verifiers. Circom operates over BN254's
scalar field (r ≈ 2^254), but Solidity `uint256` goes up to 2^256 − 1.

Values in `[r, 2^256 − 1]` are valid in Solidity but wrap modulo `r` in the
circuit. An attacker can submit `sessionNonce = n + r` which the contract treats
as a new nonce (bypassing `usedNonces[n]`) while the circuit reduces it to `n`.

## Solution

1. **`FieldBoundLib.sol`** — library with `FIELD_MODULUS` constant and
   `assertInField(uint256)` that reverts with `FieldModulusExceeded(value)`.

2. **`IdentityRegistry.sol`** — calls `assertInField()` on every public signal
   at the top of `verifyHandshake()` and `verifyDelegation()`, before nonce
   dedup, root checks, or verifier calls.

3. **Hardhat tests** (`FieldOverflow.test.ts`) — covers valid signals, wrap
   attacks (`n + r`), `uint256` max, boundary values, and nonce bypass.

4. **Certora spec** (`FieldBound.spec`) — proves all public signals reaching
   verifiers are < `FIELD_MODULUS` and that `(n, n+r)` cannot both succeed.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `contracts/src/FieldBoundLib.sol` | Library | BN254 field modulus + assertInField |
| `contracts/src/IdentityRegistry.sol` | Contract | Registry with field-bound checks |
| `contracts/test/FieldOverflow.test.ts` | Test | Hardhat tests for overflow rejection |
| `contracts/certora/specs/FieldBound.spec` | Spec | CVL rules for formal verification |
| `contracts/certora/confs/FieldBound.conf` | Config | Certora Prover configuration |
| `docs/security/field-overflow-mitigation.md` | Docs | Security note with full write-up |

## Usage

### Run Tests

```bash
cd contracts
npx hardhat test test/FieldOverflow.test.ts
```

### Run Certora Verification

```bash
certoraRun contracts/certora/confs/FieldBound.conf
```

### Key Constants

```
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

This is the BN254 scalar field order. All public signals must be strictly less
than this value.

## Public Signals Checked

### HumanUniqueness (5 signals)
| Index | Signal | Source |
|-------|--------|--------|
| 0 | nullifierHash | circuit output |
| 1 | nonceBinding | circuit output |
| 2 | humanMerkleRoot | public input |
| 3 | externalNullifier | public input |
| 4 | sessionNonce | public input |

### AgentPolicy (6 signals)
| Index | Signal | Source |
|-------|--------|--------|
| 0 | credentialHash | circuit output |
| 1 | nonceBinding | circuit output |
| 2 | agentMerkleRoot | public input |
| 3 | currentTimestamp | public input |
| 4 | requiredPermissions | public input |
| 5 | sessionNonce | public input |

### Delegation (6 signals)
| Index | Signal | Source |
|-------|--------|--------|
| 0 | delegationHash | circuit output |
| 1 | narrowedPermissions | circuit output |
| 2 | nonceBinding | circuit output |
| 3 | delegationMerkleRoot | public input |
| 4 | currentTimestamp | public input |
| 5 | sessionNonce | public input |
