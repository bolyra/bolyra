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
| `sdk/src/verifier.ts` | SDK | Updated `verifyHandshake` with `HUMAN_ROOT_STALE` error code |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | Spec | IETF draft with staleness window documentation |
| `spec/did-method-bolyra.md` | Spec | DID method with Proof Freshness section |
| `docs/owasp-agentic-mapping.md` | Docs | OWASP mapping with Replay/Staleness entry |

## Usage

### Running Tests

```bash
# From the contracts/ directory
npx hardhat test test/IdentityRegistry.humanRootHistory.test.ts
```

### SDK Verification

```typescript
import { verifyHandshake, BolyraErrorCode } from "@bolyra/sdk";

const result = await verifyHandshake(humanProof, agentProof, nonce, {
  provider: "https://sepolia.base.org",
  registryAddress: "0x...",
});

if (result.errorCode === BolyraErrorCode.HUMAN_ROOT_STALE) {
  // Proof was generated too long ago — human root evicted from buffer.
  // Ask the prover to regenerate against the current root.
}
```

### Staleness Window Calculation

```
T_stale = ROOT_HISTORY_SIZE × avg_enrollment_interval
        = 30 × 1 min = 30 min  (high throughput)
        = 30 × 1 hr  = 30 hr   (low throughput)
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

## References

- IETF Draft: `spec/draft-bolyra-mutual-zkp-auth-01.md`
- DID Method: `spec/did-method-bolyra.md`
- OWASP Mapping: `docs/owasp-agentic-mapping.md`
- Semaphore v4: https://semaphore.pse.dev
