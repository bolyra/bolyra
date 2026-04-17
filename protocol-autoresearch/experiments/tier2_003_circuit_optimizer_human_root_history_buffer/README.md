# Experiment: Human Root History Buffer

**ID**: `circuit_optimizer_human_root_history_buffer`
**Priority**: Critical | **Dimension**: Correctness | **Effort**: Hours

## Problem

`IdentityRegistry.sol` maintains a 30-root ring buffer for the agentTree but only a single root for the humanTree. New human enrollments immediately invalidate in-flight `HumanUniqueness` proofs — a liveness bug under any non-trivial enrollment throughput.

## Solution

Add a parallel `uint256[30] humanRootHistory` ring buffer with:
- `_pushHumanRoot()` internal helper (mirrors `_pushAgentRoot()`)
- `isValidHumanRoot()` view function for off-chain pre-checks
- Updated `verifyHandshake()` to scan the buffer instead of comparing a single root

No circuit changes required.

## Artifacts

| File | Description |
|---|---|
| `contracts/IdentityRegistry.sol` | Contract with dual ring buffers |
| `test/IdentityRegistry.humanRootHistory.t.sol` | Foundry test suite (14 tests) |
| `docs/specs/human-root-history.md` | Spec: invariants, rationale, migration notes |

## Running Tests

```bash
# From this experiment directory (requires Foundry)
forge test --match-contract IdentityRegistryHumanRootHistory -vvv
```

### Test Coverage

| Test | What It Verifies |
|---|---|
| `test_freshDeploy_zeroSlotsInvalid` | Zero-initialized buffer rejects all roots |
| `test_normalFill_allRootsValid` | 30 enrollments → all 30 roots valid |
| `test_eviction_oldestRootInvalid` | 31st enrollment evicts root #1 |
| `test_wrapAround_multipleWraps` | 75 enrollments → only last 30 valid |
| `test_verifyHandshake_staleHumanRootFails` | Evicted root rejected in handshake |
| `test_verifyHandshake_validBufferedRootSucceeds` | Oldest buffered root accepted |
| `test_verifyHandshake_latestRootSucceeds` | Latest root accepted |
| `test_verifyHandshake_nullifierReplayRejected` | Double-spend nullifier blocked |
| `test_concurrent_enrollAndVerify` | Prover root survives 6 concurrent enrollments |
| `test_enrollHuman_zeroRootReverts` | Zero root rejected on enrollment |
| `test_isValidHumanRoot_zeroAlwaysFalse` | Zero never valid even with filled buffer |
| `test_agentBuffer_independentFromHuman` | Buffers don't interfere |
| `test_enrollHuman_nonOperatorReverts` | Access control enforced |
| `test_historyIndex_incrementsCorrectly` | Monotonic index tracking |

## Gas Impact

- **enrollHuman()**: +1 SSTORE (~20,000 gas for buffer write)
- **verifyHandshake()**: +30 SLOADs worst case (~62,400 gas) — negligible vs. pairing check (~200k+)
