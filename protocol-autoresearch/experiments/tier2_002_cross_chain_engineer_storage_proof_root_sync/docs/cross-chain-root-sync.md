# Cross-Chain Root Sync — Developer Guide

## Overview

The cross-chain root sync system propagates identity Merkle roots from the
**Base IdentityRegistry** to **Arbitrum** and **Polygon** using EIP-1186
storage proofs. No bridges or oracles are required — verification is pure
cryptographic proof against the L1 state root.

## Architecture

| Component | Description |
|-----------|-------------|
| `StorageProofLib.sol` | Verifies EIP-1186 Merkle-Patricia trie proofs on-chain |
| `RootRelay.sol` | Accepts proofs and updates shadow roots per destination L2 |
| `ChainRegistry.sol` | Maps chainId to RootRelay and L1 oracle addresses |
| `relayer/` | TypeScript off-chain relayer that fetches proofs and submits txs |

## Deployment

### Prerequisites

- Foundry installed (`forge`, `cast`)
- Node.js 20+
- RPC endpoints for Base Sepolia, Arbitrum Sepolia, Polygon Amoy
- Funded deployer wallet on each testnet

### Step 1: Deploy StorageProofLib

StorageProofLib is a library — it gets linked into RootRelay at deploy time.

```bash
forge create contracts/StorageProofLib.sol:StorageProofLib \
  --rpc-url $ARBITRUM_SEPOLIA_RPC \
  --private-key $DEPLOYER_KEY
```

Repeat for Polygon Amoy.

### Step 2: Deploy RootRelay

```bash
forge create contracts/RootRelay.sol:RootRelay \
  --rpc-url $ARBITRUM_SEPOLIA_RPC \
  --private-key $DEPLOYER_KEY \
  --constructor-args \
    $SOURCE_REGISTRY_ADDRESS \
    0x0000000000000000000000000000000000000000000000000000000000000003 \
    0x0000000000000000000000000000000000000000000000000000000000000004 \
    $L1_BLOCK_ORACLE_ADDRESS \
    $OWNER_ADDRESS \
  --libraries contracts/StorageProofLib.sol:StorageProofLib:$LIB_ADDRESS
```

### Step 3: Deploy ChainRegistry

```bash
forge create contracts/ChainRegistry.sol:ChainRegistry \
  --rpc-url $ARBITRUM_SEPOLIA_RPC \
  --private-key $DEPLOYER_KEY \
  --constructor-args $OWNER_ADDRESS
```

Register chains:

```bash
cast send $CHAIN_REGISTRY "registerChain(uint256,address,address)" \
  421614 $ARBITRUM_ROOT_RELAY $ARBITRUM_L1_ORACLE \
  --rpc-url $ARBITRUM_SEPOLIA_RPC \
  --private-key $OWNER_KEY
```

### Step 4: Configure and Run the Relayer

```bash
cd relayer
npm install
```

Set environment variables:

```bash
export BASE_RPC_URL="https://sepolia.base.org"
export SOURCE_REGISTRY="0x..."
export AGENT_ROOT_SLOT="0x0000000000000000000000000000000000000000000000000000000000000003"
export HUMAN_ROOT_SLOT="0x0000000000000000000000000000000000000000000000000000000000000004"
export RELAYER_PRIVATE_KEY="0x..."
export ARBITRUM_RPC_URL="https://sepolia-rollup.arbitrum.io/rpc"
export ARBITRUM_ROOT_RELAY="0x..."
export POLYGON_RPC_URL="https://rpc-amoy.polygon.technology"
export POLYGON_ROOT_RELAY="0x..."
export POLL_INTERVAL_MS="60000"
```

Run:

```bash
npx ts-node relayer/src/relayRoots.ts
```

## Monitoring

### Events to Watch

- `RootUpdated(uint256 blockNumber, bytes32 agentRoot, bytes32 humanRoot)` on each RootRelay.
- Monitor `lastRelayedBlock()` to detect relayer stalls.

### Recommended Alerts

| Metric | Threshold | Action |
|--------|-----------|--------|
| Time since last `RootUpdated` | > 30 min | Check relayer health |
| Relayer wallet balance | < 0.01 ETH | Fund wallet |
| Gas price spike | > 5x baseline | Pause non-critical relays |

### Log Format

The relayer logs in structured format:

```
[relayer] Finalized block #12345, stateRoot: 0xabc...
[relayer] Arbitrum Sepolia: submitting proof for block #12345...
[relayer] Arbitrum Sepolia: root relayed in tx 0xdef... (gas: 350000)
```

## Adding a New L2 Chain

1. Identify the L1 block hash oracle on the new chain.
2. Deploy `StorageProofLib` + `RootRelay` on the new chain.
3. Register via `ChainRegistry.registerChain(chainId, rootRelay, l1Oracle)`.
4. Add the chain to the relayer's `targets` configuration.
5. Restart the relayer.

No redeployment of existing contracts is needed.

## Testing

### Solidity Tests

```bash
forge test --match-contract StorageProofLibTest -vvv
forge test --match-contract RootRelayTest -vvv
```

### TypeScript Tests

```bash
cd relayer
npx jest
```

## Testnet Deployment Addresses

| Chain | Contract | Address |
|-------|----------|---------|
| Arbitrum Sepolia | StorageProofLib | TBD |
| Arbitrum Sepolia | RootRelay | TBD |
| Arbitrum Sepolia | ChainRegistry | TBD |
| Polygon Amoy | StorageProofLib | TBD |
| Polygon Amoy | RootRelay | TBD |

## Security

See [specs/storage-proof-root-sync.md](../specs/storage-proof-root-sync.md) for the
full security model, trust assumptions, and finality analysis.