# Human Root History Buffer — Formal Specification

## 1. Problem Statement

`IdentityRegistry.sol` maintains a 30-root history buffer for the **agentTree** (`agentRootHistory`, `agentRootExists`) but previously stored only a single root for the **humanTree** (`humanRoot`). This creates a **liveness bug under load**: any new human enrollment immediately overwrites the on-chain root, invalidating all in-flight `HumanUniqueness` proofs.

Given Groth16 proving time of ~10–15 seconds on mobile hardware, even modest enrollment throughput (2–3 per block on a 12-second L2) can deterministically fail proofs.

## 2. Solution

Add a parallel `uint256[30] humanRootHistory` ring buffer with:
- `mapping(uint256 => bool) humanRootExists` for O(1) validity lookup
- `_pushHumanRoot()` internal helper (mirrors `_pushAgentRoot()`)
- `isValidHumanRoot()` public view function
- Updated `verifyHandshake()` to check `humanRootExists` instead of live-tree equality

No circuit changes required. The ZK circuits commit to a Merkle root as a public input; changing from a single-root check to a mapping lookup is purely a Solidity-side modification.

## 3. Storage Variables

```solidity
uint256[30] public humanRootHistory;           // Ring buffer of recent roots
uint256     public humanRootHistoryIndex;       // Monotonic counter (never resets)
mapping(uint256 => bool) public humanRootExists; // O(1) validity lookup
uint256     public humanRoot;                   // Canonical latest root (backward-compat)
```

## 4. Ring Buffer Mechanics

```
_pushHumanRoot(newRoot):
    slot ← humanRootHistoryIndex % 30
    expiredRoot ← humanRootHistory[slot]
    if expiredRoot ≠ 0:
        humanRootExists[expiredRoot] ← false     // evict
    humanRootHistory[slot] ← newRoot
    humanRootExists[newRoot] ← true              // register
    humanRootHistoryIndex++
    emit HumanRootAdded(newRoot, slot)
```

- **Write slot**: `index % 30` — overwrites the oldest entry when the buffer is full
- **Index is monotonic**: never wraps to zero; only the modular position wraps
- **Zero guard**: `isValidHumanRoot(0)` always returns `false`
- **O(1) lookup**: `humanRootExists` mapping kept in sync via explicit eviction

## 5. Formal Invariants

### INV-1: Buffer Population

After `n` enrollments, the buffer contains exactly `min(n, 30)` non-zero roots.

```
∀n ∈ ℕ: |{i ∈ [0,30) : humanRootHistory[i] ≠ 0}| = min(n, 30)
```

### INV-2: Mapping–Buffer Consistency

`humanRootExists[r]` is `true` if and only if `r` appears in the current buffer window.

```
∀r ∈ uint256, r ≠ 0:
    humanRootExists[r] = true ⟺ ∃i ∈ [0,30) : humanRootHistory[i] = r
```

### INV-3: Window Validity

The 30 most recent roots are always valid.

```
∀k ∈ [max(0, n-30), n):
    isValidHumanRoot(root_k) = true
```

where `root_k` is the root pushed at enrollment index `k`.

### INV-4: Eviction Correctness

Roots older than 30 enrollments are evicted (overwritten) and no longer in the buffer.

```
∀k < max(0, n-30):
    isValidHumanRoot(root_k) = false
    (assuming all roots are distinct)
```

### INV-5: Zero Root Rejection

```
isValidHumanRoot(0) = false    (unconditionally)
```

### INV-6: Canonical Root Currency

```
humanRoot = root_{n-1}    (always equals the latest enrollment root)
```

### INV-7: Buffer Independence

Human and agent root buffers do not interfere with each other.

```
∀ enrollment on humanTree: agentRootHistory unchanged ∧ agentRootExists unchanged
∀ enrollment on agentTree: humanRootHistory unchanged ∧ humanRootExists unchanged
```

## 6. Liveness Argument

**Claim**: A proof generated immediately before any enrollment remains valid for up to 29 subsequent enrollments.

**Proof**: Let `root_k` be the root captured by the prover. After the prover captures `root_k`, the next enrollment writes to slot `(k+1) % 30`. The slot containing `root_k` is at position `k % 30`. This slot is only overwritten when enrollment index reaches `k + 30`, which requires 30 new enrollments. Therefore `root_k` remains in the buffer for enrollments `k+1` through `k+29` (inclusive), providing a window of 29 concurrent enrollments.

At steady-state enrollment rate of 2 per block (12-second L2 blocks), this window covers:
```
29 enrollments ÷ 2 per block × 12 seconds/block = 174 seconds ≈ 2.9 minutes
```

This exceeds the ~15-second Groth16 proving time by >10×.

## 7. Security Argument

**Claim**: A stale root beyond the buffer window is correctly rejected.

**Proof**: When enrollment index reaches `k + 30`, `_pushHumanRoot` writes to slot `k % 30`, overwriting `root_k`. Before overwriting, it sets `humanRootExists[root_k] = false`. The new root is written and `humanRootExists[newRoot] = true`. Since `root_k` is no longer in any buffer slot and its mapping entry is `false`, `isValidHumanRoot(root_k)` returns `false`, and `verifyHandshake` reverts with `InvalidHumanRoot`.

**Edge case — duplicate roots**: If `root_k = root_j` for some `j > k` still in the window, the eviction of `root_k` from its slot would set `humanRootExists[root_k] = false` even though the same value exists at slot `j % 30`. This is a theoretical concern but not a practical one: Merkle roots are collision-resistant, so distinct enrollments produce distinct roots with overwhelming probability. The ring buffer approach (shared with Semaphore v4 and WorldID) accepts this as a negligible risk.

## 8. Buffer Depth Rationale

| Parameter | Value |
|---|---|
| Buffer size | 30 slots |
| Assumed prove time | ~15 seconds (Groth16 mobile) |
| Assumed block time | ~12 seconds (Optimism/Base) |
| Enrollment rate | ≤2 per block (steady state) |
| Effective window | 29 enrollments ÷ 2/block × 12s = ~174s (~3 min) |
| Worst-case window | 29 enrollments × 1/block × 12s = ~348s (~6 min) |
| Target liveness margin | ≥10× prove time |

## 9. Gas Impact

| Function | Delta | Notes |
|---|---|---|
| `enrollHuman()` | +1 SSTORE (buffer) +1 SSTORE (mapping set true) +1 SSTORE (mapping set false, warm after first wrap) | ~40,000 gas first fill; ~25,000 gas after warm |
| `verifyHandshake()` | -30 SLOADs (removed linear scan) +1 SLOAD (mapping lookup) | Net savings of ~60,000 gas vs linear scan |
| `isValidHumanRoot()` | O(1) mapping read vs O(30) linear scan | ~2,100 gas vs ~62,400 gas worst case |
