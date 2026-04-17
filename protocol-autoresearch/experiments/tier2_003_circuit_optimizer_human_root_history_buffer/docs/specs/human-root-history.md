# Human Root History Buffer — Specification

## Problem Statement

`IdentityRegistry.sol` maintains a 30-root history buffer for the **agentTree** (`agentRootHistory`) but stores only a single root for the **humanTree** (`humanRoot`). This creates a **liveness bug under load**: any new human enrollment immediately overwrites the on-chain root, invalidating all in-flight `HumanUniqueness` proofs.

Given Groth16 proving time of ~10–15 seconds on mobile hardware, even modest enrollment throughput (2–3 per block on a 12-second L2) can deterministically fail proofs.

## Solution

Add a parallel `uint256[30] humanRootHistory` ring buffer with identical semantics to the existing `agentRootHistory`.

### No Circuit Changes Required

The ZK circuits commit to a Merkle root as a public input. The verifier contract checks whether that root is "known." Changing from a single-root check to a buffer scan is purely a Solidity-side modification — the circuit, proving key, and verification key remain unchanged.

## Buffer Depth Rationale

| Parameter | Value |
|---|---|
| Buffer size | 30 slots |
| Assumed prove time | ~15 seconds (Groth16 mobile) |
| Assumed block time | ~12 seconds (Optimism/Base) |
| Enrollment rate | ≤2 per block (steady state) |
| Effective window | 30 roots ÷ 2 per block × 12s = **~180 seconds (3 minutes)** |
| Worst-case window | 30 roots × 1 per block × 12s = **~360 seconds (6 minutes)** |
| Target liveness margin | ≥2× prove time = 30 seconds covered |

At steady state (2 enrollments/block), the buffer provides a **3-minute window** — well above the ~15-second proving time. Even under burst conditions (1 enrollment per block), the buffer provides 6 minutes of validity.

The 30-slot size matches the agentTree buffer for consistency and simplicity. Increasing the buffer trades storage gas (cold SLOAD per slot on verification) for a wider liveness window.

## Storage Layout

```solidity
// Immediately after agent tree equivalents:
uint256[30] public humanRootHistory;     // Ring buffer
uint256 public humanRootHistoryIndex;    // Monotonic counter (never resets)
uint256 public humanRoot;                // Canonical latest root (backward-compat)
```

### Ring Buffer Mechanics

```
_pushHumanRoot(newRoot):
    humanRootHistory[humanRootHistoryIndex % 30] = newRoot
    humanRootHistoryIndex++
```

- **Write slot**: `index % 30` — overwrites the oldest entry when the buffer is full
- **Index is monotonic**: never wraps to zero; only the modular position wraps
- **Zero guard**: `isValidHumanRoot(0)` always returns `false`, preventing zero-initialized slots from matching

## Contract Invariants

1. **INV-1: Buffer contains exactly min(enrollmentCount, 30) non-zero roots**
   After `n` enrollments, the buffer holds `min(n, 30)` valid roots.

2. **INV-2: The 30 most recent roots are always valid**
   For any root pushed at index `i` where `i >= humanRootHistoryIndex - 30`, `isValidHumanRoot(root)` returns `true`.

3. **INV-3: Roots older than 30 enrollments are evicted**
   For any root pushed at index `i` where `i < humanRootHistoryIndex - 30`, the root has been overwritten and is no longer in the buffer.

4. **INV-4: Zero root is never valid**
   `isValidHumanRoot(0)` returns `false` regardless of buffer state.

5. **INV-5: Canonical `humanRoot` always equals the latest root**
   After each enrollment, `humanRoot` is updated for backward compatibility with contracts and SDKs that read the single root.

6. **INV-6: Buffers are independent**
   Human and agent root buffers do not interfere with each other. An enrollment on one tree does not affect the other tree's buffer.

## verifyHandshake() Changes

**Before (single root):**
```solidity
require(humanRoot == proof.humanRoot, "invalid human root");
```

**After (buffer scan):**
```solidity
if (!isValidHumanRoot(proof.humanRoot)) {
    revert InvalidHumanRoot(proof.humanRoot);
}
```

The `isValidHumanRoot()` function iterates all 30 slots. Worst-case gas cost is 30 cold SLOADs (~62,400 gas). This is acceptable for a verification transaction that already includes pairing-check gas (~200,000+).

## Off-Chain SDK Integration

### isValidHumanRoot() View Helper

The `isValidHumanRoot(uint256 root) → bool` view function allows off-chain SDKs and relayers to:

1. **Pre-check** before submitting a proof transaction (avoid wasted gas)
2. **Surface retry hints** when a root has just been evicted ("root expired, re-prove with current root")
3. **Monitor buffer fill** by reading `humanRootHistoryIndex`

### Recommended SDK Flow

```
1. Read current humanRoot from contract
2. Generate ZK proof with humanRoot as public input
3. Before submitting tx, call isValidHumanRoot(capturedRoot)
4. If false → re-read humanRoot, re-generate proof
5. If true → submit verifyHandshake() transaction
```

## Migration Notes

- **No circuit changes**: Existing proving keys and verification keys remain valid
- **No data migration**: The buffer starts empty (all zeros); new enrollments populate it
- **Backward compatibility**: `humanRoot` field still holds the latest root for any contract or SDK reading it directly
- **Gas impact**: `enrollHuman()` adds one SSTORE (~20,000 gas for the buffer write). `verifyHandshake()` adds up to 30 SLOADs (~62,400 gas worst case, ~2,100 gas best case if first slot matches)
