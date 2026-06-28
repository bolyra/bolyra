# Human Root History Buffer — Experiment

## Overview

This experiment adds a `humanRootHistory[30]` ring buffer to the Bolyra
`IdentityRegistry` contract, achieving parity with the existing
`agentRootHistory[30]` pattern.

## Problem

Without a root history buffer, every new human enrollment instantly
invalidates all in-flight human proofs. During onboarding surges, proofs
generated seconds ago become stale — a showstopper for production commerce.

## Solution

Mirror the `agentRootHistory[30]` ring buffer for the human tree:

- **Storage**: `bytes32[30] public humanRootHistory` + `uint256 public humanRootHistoryIndex`
- **Write**: On each `enrollHuman()`, write the new root to `humanRootHistory[index % 30]` and increment the index
- **Read**: `_isValidHumanRoot()` iterates all 30 slots; any match returns `true`
- **Eviction**: After 30 subsequent enrollments, the oldest root is overwritten

## Artifacts

| File | Description |
|------|-------------|
| `contracts/src/IdentityRegistry.sol` | Contract with both human and agent ring buffers |
| `contracts/src/interfaces/IIdentityRegistry.sol` | Interface with `isValidHumanRoot()` view function |
| `contracts/test/IdentityRegistry.humanRootHistory.test.ts` | 7 Hardhat tests covering ring buffer correctness |
| `sdk/src/verify.ts` | SDK `verifyHandshake()` using `isValidHumanRoot()` on-chain |
| `spec/did-method-bolyra.md` | DID spec with 30-root history window documentation |
| `docs/quickstart.md` | Quickstart with proof validity callout |

## Usage

```bash
# Run contract tests
npm run test:contracts

# Run just the ring buffer tests
npx hardhat test contracts/test/IdentityRegistry.humanRootHistory.test.ts

# TypeScript type check
cd sdk && npm run typecheck
```

## Design Decisions

1. **30 slots** — Matches Semaphore v4 / World ID convention. Provides
   practical concurrency tolerance without excessive gas cost.

2. **Enrollment-count-based eviction** — The validity window is tied to
   enrollment rate, not wall clock. This is intentional: during quiet
   periods proofs stay valid longer; during surges the window tightens.

3. **Ring buffer (not mapping)** — Fixed-size array avoids dynamic storage
   allocation costs. The 30-iteration linear scan in `_isValidHumanRoot()`
   costs ~6,000 gas — negligible for a view function.

4. **`HumanRootHistoryUpdated` event** — Enables off-chain indexers to
   track root history without polling storage slots.

## Verification

- All 7 test scenarios pass (boundary, wraparound, eviction, interleaving)
- Agent root history remains unaffected (isolation test)
- SDK `verifyHandshake()` works in both on-chain and off-chain modes
- DID spec and quickstart document the 30-root window semantics
