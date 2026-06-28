# Experiment: Human Root History Parity (standards_architect)

## Summary

This experiment adds a `ROOT_HISTORY_SIZE` (30) ring buffer for human
Merkle tree roots in the IdentityRegistry contract, matching the
existing agent tree buffer. Without this buffer, any new human
enrollment immediately invalidates in-flight proofs — a protocol-level
correctness gap.

## Problem

The IdentityRegistry maintained a 30-root history buffer for the
agent tree but used only a single root slot for the human tree. This
meant:

1. Any new human enrollment instantly invalidated all in-flight proofs.
2. High enrollment throughput caused proof failures for legitimate users.
3. Asymmetric behavior between human and agent trees created confusing UX.

## Solution

Add a parallel `humanRootHistory[30]` ring buffer with identical
semantics to `agentRootHistory[30]`:

- `humanRootHistory[humanRootHistoryIndex % 30] = newRoot`
- `isKnownHumanRoot()` iterates all 30 slots
- Zero root is always rejected
- `HumanRootHistoryUpdated` event emitted on each enrollment

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `contracts/src/IdentityRegistry.sol` | Contract | Full registry with parallel ring buffers |
| `contracts/src/IIdentityRegistry.sol` | Interface | Extended with `isKnownHumanRoot`, `HumanRootHistoryUpdated` |
| `contracts/test/IdentityRegistry.humanRootHistory.test.ts` | Test | 10 Hardhat tests covering buffer semantics |
| `sdk/src/registry.ts` | SDK | `RegistryClient` with `isKnownHumanRoot` pre-flight checks |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | Spec | IETF draft with humanTree liveness section |
| `spec/did-method-bolyra.md` | Spec | DID method with humanTree state transitions note |
| `docs/root-history-parity.md` | Docs | Liveness guarantee, window sizing, operator guidance |

## Usage

### Running Tests

```bash
# From the contracts/ directory
npx hardhat test test/IdentityRegistry.humanRootHistory.test.ts
```

### SDK Pre-flight Check

```typescript
import { RegistryClient } from "@bolyra/sdk";

const client = new RegistryClient({
  provider: "https://sepolia.base.org",
  registryAddress: "0x...",
});

const status = await client.checkHumanRoot(myProof.humanMerkleRoot);
if (!status.isKnown) {
  // Root evicted from buffer — regenerate proof against current root
}
```

### Staleness Window Calculation

```
T_stale = ROOT_HISTORY_SIZE * avg_enrollment_interval
        = 30 * 1 min = 30 min  (high throughput)
        = 30 * 1 hr  = 30 hr   (low throughput)
```

## Key Design Decisions

1. **Shared ROOT_HISTORY_SIZE=30**: Both trees use the same buffer
   depth to avoid asymmetric proof expiry in mutual handshakes.

2. **Ring buffer (not mapping)**: Bounded storage cost (30 slots)
   vs. unbounded mapping growth. Gas-efficient iteration for lookups.

3. **Zero-root rejection**: Prevents false positives from uninitialized
   buffer slots.

4. **Event emission**: `HumanRootHistoryUpdated` enables off-chain
   indexers to track root freshness without polling.

## Circuit Impact

No circuit changes required. `humanMerkleRoot` is already a public
output of the HumanUniqueness circuit. The history buffer check is
purely in the verifier contract — the circuit remains unchanged.

## References

- IETF Draft: `spec/draft-bolyra-mutual-zkp-auth-01.md`
- DID Method: `spec/did-method-bolyra.md`
- Root History Docs: `docs/root-history-parity.md`
- Semaphore v4: https://semaphore.pse.dev
