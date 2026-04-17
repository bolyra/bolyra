# Experiment: Human Root History Buffer

**ID**: `formal_verifier_human_root_history_buffer`  
**Persona**: Formal Verifier  
**Priority**: High | **Dimension**: Correctness | **Effort**: Hours

## Problem

`IdentityRegistry.sol` maintains a 30-root ring buffer for the agentTree but only a single root for the humanTree. New human enrollments immediately invalidate in-flight `HumanUniqueness` proofs — a **liveness bug** under any non-trivial enrollment throughput.

## Solution

Add a parallel `uint256[30] humanRootHistory` ring buffer with O(1) `humanRootExists` mapping lookup. Update `enrollHuman()` to push roots into the buffer with explicit eviction, and update `verifyHandshake()` to check the mapping instead of a single root.

No circuit changes required.

## Artifacts

| File | Description |
|---|---|
| `contracts/IdentityRegistry.sol` | Contract with dual ring buffers + O(1) mapping lookups |
| `test/IdentityRegistry.humanRootBuffer.t.sol` | Foundry test suite (fuzz + unit, 18 tests) |
| `specs/human_root_history_buffer.md` | Formal spec: invariants, liveness/safety proofs, gas analysis |
| `docs/protocol-changes/human-root-buffer.md` | Migration notes, ABI changes, upgrade path |

## Running Tests

```bash
# From this experiment directory (requires Foundry)
forge test --match-contract IdentityRegistryHumanRootBuffer -vvv
```

## Key Design Decisions

### O(1) Mapping vs Linear Scan

The prior implementation used a linear scan (`for i in 0..30: if buffer[i] == root`) costing up to 30 cold SLOADs (~62,400 gas). This version adds a `humanRootExists` mapping that is kept in sync with the ring buffer via explicit eviction on each push. Verification drops to a single SLOAD (~2,100 gas).

The tradeoff: enrollment is ~20,000 gas more expensive (2 extra SSTOREs for mapping set/unset). Since verification happens far more frequently than enrollment, this is a net protocol-wide gas improvement.

### Monotonic Index

The `humanRootHistoryIndex` counter increments monotonically and never wraps. Only the modular write position (`index % 30`) wraps. This avoids ambiguity between "buffer empty" and "buffer full" states and provides a total enrollment counter for off-chain indexing.

## Test Coverage

| Category | Tests |
|---|---|
| **(1) Any-of-30 acceptance** | `test_proofAccepted_anyOf30HistoricalRoots` |
| **(2) Stale root rejection** | `test_proofRejected_rootOlderThanWindow`, `test_proofRejected_multipleEvictions` |
| **(3) Wraparound correctness** | `test_bufferWraparound_indexCorrectness`, `test_bufferWraparound_secondWrap` |
| **(4) Event emission** | `test_enrollHuman_emitsHumanRootAdded`, `test_enrollHuman_emitsCorrectSlotAtWrap` |
| **(5) Buffer independence** | `test_concurrent_noBufferCorruption`, `test_concurrent_handshakeWithBothBuffers` |
| **Edge cases** | Zero root, non-operator, nullifier replay, canonical root, index tracking |
| **Fuzz** | `testFuzz_enrollAndValidate`, `testFuzz_mappingConsistentWithBuffer` |

## Gas Impact

| Function | Before | After | Delta |
|---|---|---|---|
| `enrollHuman()` | ~45k | ~65k | +20k |
| `verifyHandshake()` (human check) | ~62k worst | ~2.1k | **-60k** |
| `isValidHumanRoot()` | ~62k worst | ~2.1k | **-60k** |
