# Storage Proof Root Sync — Protocol Specification

## 1. Overview

This specification describes a trustless mechanism for synchronizing Merkle roots
(`agentRootHistory` and `humanRootHistory`) from the **Base IdentityRegistry** to
**Arbitrum** and **Polygon** L2 chains using **EIP-1186 storage proofs**.

The design avoids bridges, oracles, and multisigs. Verification is pure cryptographic
proof against the L1 state root anchor available on each L2.

## 2. Architecture

```
Base (source)           L1 (Ethereum)            Arbitrum / Polygon (destination)
┌──────────────┐       ┌──────────────┐          ┌──────────────────┐
│ Identity     │       │  L1 Block    │          │  RootRelay       │
│ Registry     │──────▶│  Headers     │◀─────────│  (verifies proof │
│              │       │              │          │   against L1     │
│ slot[3]: agentRoot   │  stateRoot   │          │   state root)    │
│ slot[4]: humanRoot   └──────────────┘          │                  │
└──────────────┘                                 │  agentRoot ✓     │
       │                                         │  humanRoot ✓     │
       │         Relayer (off-chain)              └──────────────────┘
       │         ┌────────────────────┐                    ▲
       └────────▶│ eth_getProof       │────────────────────┘
                 │ encode + submit    │
                 └────────────────────┘
```

## 3. Storage Slot Derivation

The Base IdentityRegistry uses Solidity storage layout:

```solidity
// Slot 3: mapping(uint256 => bytes32) agentRootHistory
// Slot 4: mapping(uint256 => bytes32) humanRootHistory
```

For the **latest** root (key = current epoch):

```
agentRootSlot = keccak256(abi.encode(epoch, 3))
humanRootSlot = keccak256(abi.encode(epoch, 4))
```

For the **current active root** (stored as a simple `bytes32`):

```
agentRootSlot = 0x03  (slot index 3)
humanRootSlot = 0x04  (slot index 4)
```

The relayer configuration specifies which slot derivation method to use.

## 4. Trusted L1 Anchor

### 4.1 Arbitrum

Arbitrum exposes L1 block data via the **L1Block** precompile at
`0x4200000000000000000000000000000000000015`:

- `L1Block.hash()` — returns the latest L1 block hash posted by the sequencer.
- `ArbSys(0x64).arbBlockHash(blockNumber)` — returns L1 block hash for a given number.

The `RootRelay` on Arbitrum calls the L1 oracle to retrieve the trusted block hash,
then verifies the submitted state root is consistent with that block.

### 4.2 Polygon PoS

Polygon PoS receives L1 state via **Heimdall checkpoints**. The `StateReceiver`
contract receives periodic L1 state commitments. The `RootRelay` on Polygon uses:

- `block.blockhash()` for recent blocks (within 256 blocks of last checkpoint).
- A governance-approved L1 block oracle for older blocks.

### 4.3 Trust Model

The relayer is **untrusted** — it can only submit valid proofs. A malicious relayer
cannot forge a proof because:

1. The L1 block hash is sourced from the L2's native L1 anchor (sequencer-posted).
2. The Merkle-Patricia trie proof is verified on-chain against that state root.
3. Block number monotonicity prevents replaying old (lower) roots.

**Trust assumptions:**
- The L2 sequencer posts correct L1 block hashes (standard L2 security assumption).
- The L1 state root in the block header is correct (Ethereum consensus).
- Base settles to L1 within a reasonable finality window.

## 5. Proof Submission Flow

1. Relayer polls Base for the latest **finalized** block.
2. Relayer calls `eth_getProof(registryAddress, [agentSlot, humanSlot], blockNumber)`.
3. Relayer RLP-encodes the proof nodes.
4. Relayer submits `relayRoots(blockNumber, stateRoot, accountProof, agentProof, humanProof)`
   to each target L2's `RootRelay`.
5. `RootRelay` verifies:
   - `blockNumber > lastRelayedBlock` (monotonicity).
   - L1 block hash from oracle matches.
   - Account proof verifies against state root.
   - Storage proofs verify against account's storage root.
6. Shadow roots updated, `RootUpdated` event emitted.

## 6. Replay Protection

The `lastRelayedBlock` state variable enforces strict monotonicity:

```solidity
require(blockNumber > lastRelayedBlock, "BlockNumberNotMonotonic");
```

This prevents:
- Replaying the same proof twice.
- Submitting an older proof to roll back roots.
- Front-running with stale data.

## 7. Security Considerations

### 7.1 Finality

The relayer should only submit proofs for **finalized** blocks on Base.
Base achieves L1-equivalent finality after its state root is posted to Ethereum L1
and confirmed. Using `"finalized"` block tag ensures this.

### 7.2 Proof Validity Window

L2 block oracles may only serve recent L1 block hashes (e.g., last 256 blocks).
The relayer must submit proofs within this window. If the window is missed,
the relayer waits for the next finalized block.

### 7.3 Gas Costs

Merkle-Patricia trie verification is gas-intensive (~200k-500k gas per proof).
Two storage proofs share the same account proof, so total gas per relay is
approximately 300k-700k gas on the destination L2.

### 7.4 Liveness

If the relayer goes down, roots become stale but never incorrect.
Anyone can run a relayer — the function is permissionless.

## 8. Upgrade Path

New L2 chains are added via `ChainRegistry.registerChain()` without any
redeployment of core contracts. The relayer configuration is updated to
include the new target chain's RPC URL and `RootRelay` address.