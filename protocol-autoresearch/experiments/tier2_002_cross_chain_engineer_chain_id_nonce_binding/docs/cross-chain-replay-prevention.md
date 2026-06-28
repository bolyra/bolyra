# Cross-Chain Replay Prevention in Bolyra

## Overview

Bolyra's mutual ZKP handshake protocol now binds every proof to a specific
EVM chain via `chainId`. This prevents cross-chain replay attacks where a
valid handshake proof from one chain is submitted on another.

## The Attack

### Scenario

1. Bolyra is deployed on both **Base** (chainId=8453) and **Arbitrum** (chainId=42161).
2. Both deployments share the same identity Merkle root (e.g., synced via a bridge).
3. Alice and Bot-7 complete a valid handshake on Base.
4. Eve observes the transaction and extracts `(humanProof, agentProof)` from calldata.
5. Eve submits the same proof pair to the Arbitrum `BolyraVerifier`.
6. **Without chain binding:** The proofs verify — Eve replays the handshake on Arbitrum.

### Impact

Cross-chain replay can lead to:
- Unauthorized agent actions on a different chain.
- Double-spending of single-use handshake authorizations.
- Violation of per-chain access control policies.

## The Fix: effectiveNonce

### Circuit Changes

Both `HumanUniqueness` and `AgentPolicy` circuits now accept `chainId` as a
public input and compute:

```
effectiveNonce = Poseidon2(sessionNonce, chainId)
```

The `nonceBinding` output is derived from `effectiveNonce` instead of the raw
`sessionNonce`. This makes the proof's public outputs chain-specific — the same
inputs on different chains produce different `nonceBinding` values.

### On-Chain Enforcement

`BolyraVerifier.verifyHandshake()` extracts `chainId` from both proofs' public
signals and asserts:

```solidity
if (humanChainId != block.chainid) revert ChainIdMismatch(...);
if (agentChainId != block.chainid) revert ChainIdMismatch(...);
```

This two-layer defense (circuit binding + on-chain check) ensures that:
1. The proof was generated with the correct chain in mind (circuit layer).
2. The proof is being submitted to the correct chain (contract layer).

### SDK Changes

`proveHandshake()` and `verifyHandshake()` now require a `chainId: bigint`
parameter. The SDK passes `chainId` as a public input to both circuit witnesses.

## Cost

~250–300 additional constraints per circuit (one Poseidon2 hash). Negligible
impact on proving time (~5ms with rapidsnark).

## Multi-Chain Deployment Guide

1. **Provers** must specify the target `chainId` when calling `proveHandshake()`.
2. **Each chain** needs its own proof — proofs are not portable across chains.
3. **Off-chain verifiers** should check that `chainId` in public signals matches
   the expected deployment chain, even when not using the on-chain verifier.
4. **Bridge operators** syncing Merkle roots across chains do not need changes —
   the chain binding is in the nonce commitment, not the root.

## Files Changed

| File | Change |
|------|--------|
| `circuits/src/HumanUniqueness.circom` | Added `chainId` public input, `effectiveNonce` computation |
| `circuits/src/AgentPolicy.circom` | Added `chainId` public input, `effectiveNonce` computation |
| `contracts/src/BolyraVerifier.sol` | `block.chainid` assertion before Groth16 verification |
| `contracts/src/HumanUniquenessVerifier.sol` | Regenerated from new `.zkey` (6 public signals) |
| `contracts/src/AgentPolicyVerifier.sol` | Regenerated from new `.zkey` (7 public signals) |
| `sdk/src/types.ts` | Added `chainId` to `HandshakeOptions`, `ProofInputs`, etc. |
| `sdk/src/handshake.ts` | Passes `chainId` to witnesses, checks it in `verifyHandshake()` |
