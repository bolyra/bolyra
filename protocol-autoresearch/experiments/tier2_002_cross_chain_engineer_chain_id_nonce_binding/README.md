# Experiment: Bind chainId into sessionNonce to Prevent Cross-Chain Replay

**ID:** `cross_chain_engineer_chain_id_nonce_binding`
**Priority:** Critical
**Dimension:** Correctness

## Problem

The current `sessionNonce` is chain-unaware. A valid handshake proof verified
on Base can be replayed on Arbitrum if both share the same Merkle root.

## Solution

Compute `effectiveNonce = Poseidon2(sessionNonce, chainId)` inside both
`HumanUniqueness` and `AgentPolicy` circuits, and expose `chainId` as a
public input. The on-chain verifier asserts `chainId == block.chainid`.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuits/src/HumanUniqueness.circom` | circuit | Added `chainId` public input + `effectiveNonce` |
| `circuits/src/AgentPolicy.circom` | circuit | Added `chainId` public input + `effectiveNonce` |
| `contracts/src/BolyraVerifier.sol` | contract | `block.chainid` check before Groth16 verify |
| `contracts/src/HumanUniquenessVerifier.sol` | contract | Stub (regenerate from new `.zkey`) |
| `contracts/src/AgentPolicyVerifier.sol` | contract | Stub (regenerate from new `.zkey`) |
| `sdk/src/types.ts` | SDK | `chainId` field on all handshake types |
| `sdk/src/handshake.ts` | SDK | Passes `chainId` to witnesses |
| `circuits/test/HumanUniqueness.test.js` | test | Cross-chain nonceBinding divergence tests |
| `circuits/test/AgentPolicy.test.js` | test | Mirror of HumanUniqueness cross-chain tests |
| `contracts/test/BolyraVerifier.test.ts` | test | Hardhat `block.chainid` enforcement tests |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | spec | effectiveNonce derivation + public signal tables |
| `docs/cross-chain-replay-prevention.md` | docs | Attack vector + mitigation explainer |

## Usage

### Compile circuits

```bash
npm run compile:circuits
```

### Regenerate verifier contracts

```bash
# After compile:circuits produces new .zkey files:
snarkjs zkey export solidityverifier circuits/build/HumanUniqueness.zkey contracts/src/HumanUniquenessVerifier.sol
snarkjs zkey export solidityverifier circuits/build/AgentPolicy_groth16.zkey contracts/src/AgentPolicyVerifier.sol
```

### Run circuit tests (fast — witness only)

```bash
npm run test:circuits:fast
```

### Run contract tests

```bash
npm run test:contracts
```

### Run all tests

```bash
npm test
```

### SDK usage

```typescript
import { proveHandshake } from "@bolyra/sdk";

const proof = await proveHandshake({
  // ... existing options ...
  sessionNonce: BigInt("123456789"),
  chainId: 8453n, // Base mainnet
});
```

## Constraint Cost

~250–300 additional constraints per circuit (one Poseidon2 hash for
`effectiveNonce`). Well within `pot16.ptau` capacity.

## Dependencies

- `circomlib` Poseidon template (already included)
- `pot16.ptau` universal SRS (already in `circuits/build/`)
- `snarkjs >= 0.7.x` for phase 2 setup and verifier export
- Hardhat with `block.chainid` support (EIP-1344)
