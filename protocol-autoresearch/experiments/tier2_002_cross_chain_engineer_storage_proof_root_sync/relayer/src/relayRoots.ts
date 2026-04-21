import { ethers, JsonRpcProvider, Wallet, Contract } from "ethers";
import { encodeProof, EIP1186Proof } from "./proofEncoder";

// ──────────────────────── Configuration ────────────────────────

interface RelayerConfig {
  /** Base (source chain) RPC URL */
  baseRpcUrl: string;
  /** Address of IdentityRegistry on Base */
  sourceRegistry: string;
  /** Storage slot for agentRootHistory (hex) */
  agentRootSlot: string;
  /** Storage slot for humanRootHistory (hex) */
  humanRootSlot: string;
  /** Target L2 configurations */
  targets: TargetChain[];
  /** Relayer private key */
  privateKey: string;
  /** Polling interval in ms (default: 60000) */
  pollIntervalMs?: number;
}

interface TargetChain {
  name: string;
  chainId: number;
  rpcUrl: string;
  rootRelayAddress: string;
}

// ──────────────────────── RootRelay ABI (minimal) ────────────────────────

const ROOT_RELAY_ABI = [
  "function relayRoots(uint256 blockNumber, bytes32 stateRoot, bytes[] calldata accountProof, bytes[] calldata agentStorageProof, bytes[] calldata humanStorageProof) external",
  "function lastRelayedBlock() view returns (uint256)",
  "event RootUpdated(uint256 indexed blockNumber, bytes32 agentRoot, bytes32 humanRoot)",
];

// ──────────────────────── Main Loop ────────────────────────

export async function startRelayer(config: RelayerConfig): Promise<void> {
  const baseProvider = new JsonRpcProvider(config.baseRpcUrl);
  const pollInterval = config.pollIntervalMs ?? 60_000;

  console.log(`[relayer] Starting root relay loop`);
  console.log(`[relayer] Source registry: ${config.sourceRegistry}`);
  console.log(`[relayer] Agent root slot: ${config.agentRootSlot}`);
  console.log(`[relayer] Human root slot: ${config.humanRootSlot}`);
  console.log(`[relayer] Targets: ${config.targets.map((t) => t.name).join(", ")}`);
  console.log(`[relayer] Poll interval: ${pollInterval}ms`);

  while (true) {
    try {
      await relayOnce(config, baseProvider);
    } catch (err) {
      console.error(`[relayer] Error in relay cycle:`, err);
    }
    await sleep(pollInterval);
  }
}

// ──────────────────────── Single Relay Cycle ────────────────────────

export async function relayOnce(
  config: RelayerConfig,
  baseProvider: JsonRpcProvider
): Promise<void> {
  // 1. Get the latest finalized block on Base.
  const block = await baseProvider.getBlock("finalized");
  if (!block) {
    console.warn(`[relayer] No finalized block available`);
    return;
  }
  const blockNumber = block.number;
  const stateRoot = block.stateRoot;
  console.log(
    `[relayer] Finalized block #${blockNumber}, stateRoot: ${stateRoot}`
  );

  // 2. Fetch EIP-1186 proofs for both storage slots.
  const proofResponse = await fetchStorageProof(
    baseProvider,
    config.sourceRegistry,
    [config.agentRootSlot, config.humanRootSlot],
    blockNumber
  );

  // 3. Encode proofs.
  const agentEncoded = encodeProof(proofResponse, 0);
  const humanEncoded = encodeProof(proofResponse, 1);

  // 4. Submit to each target L2.
  for (const target of config.targets) {
    try {
      await submitToTarget(
        target,
        config.privateKey,
        blockNumber,
        stateRoot,
        agentEncoded.accountProof,
        agentEncoded.storageProof,
        humanEncoded.storageProof
      );
    } catch (err) {
      console.error(`[relayer] Failed to relay to ${target.name}:`, err);
    }
  }
}

// ──────────────────────── Helpers ────────────────────────

async function fetchStorageProof(
  provider: JsonRpcProvider,
  address: string,
  slots: string[],
  blockNumber: number
): Promise<EIP1186Proof> {
  const blockHex = "0x" + blockNumber.toString(16);
  const result = await provider.send("eth_getProof", [
    address,
    slots,
    blockHex,
  ]);
  return result as EIP1186Proof;
}

async function submitToTarget(
  target: TargetChain,
  privateKey: string,
  blockNumber: number,
  stateRoot: string,
  accountProof: string[],
  agentStorageProof: string[],
  humanStorageProof: string[]
): Promise<void> {
  const provider = new JsonRpcProvider(target.rpcUrl);
  const wallet = new Wallet(privateKey, provider);
  const relay = new Contract(target.rootRelayAddress, ROOT_RELAY_ABI, wallet);

  // Check if this block has already been relayed.
  const lastBlock = await relay.lastRelayedBlock();
  if (BigInt(blockNumber) <= BigInt(lastBlock)) {
    console.log(
      `[relayer] ${target.name}: block #${blockNumber} already relayed (last: ${lastBlock})`
    );
    return;
  }

  console.log(
    `[relayer] ${target.name}: submitting proof for block #${blockNumber}...`
  );

  const tx = await relay.relayRoots(
    blockNumber,
    stateRoot,
    accountProof,
    agentStorageProof,
    humanStorageProof
  );

  const receipt = await tx.wait();
  console.log(
    `[relayer] ${target.name}: root relayed in tx ${receipt.hash} (gas: ${receipt.gasUsed})`
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ──────────────────────── CLI Entry Point ────────────────────────

if (require.main === module) {
  const config: RelayerConfig = {
    baseRpcUrl: process.env.BASE_RPC_URL ?? "https://sepolia.base.org",
    sourceRegistry:
      process.env.SOURCE_REGISTRY ??
      "0x0000000000000000000000000000000000000000",
    agentRootSlot:
      process.env.AGENT_ROOT_SLOT ??
      "0x0000000000000000000000000000000000000000000000000000000000000003",
    humanRootSlot:
      process.env.HUMAN_ROOT_SLOT ??
      "0x0000000000000000000000000000000000000000000000000000000000000004",
    privateKey: process.env.RELAYER_PRIVATE_KEY ?? "",
    pollIntervalMs: parseInt(process.env.POLL_INTERVAL_MS ?? "60000", 10),
    targets: [
      {
        name: "Arbitrum Sepolia",
        chainId: 421614,
        rpcUrl:
          process.env.ARBITRUM_RPC_URL ??
          "https://sepolia-rollup.arbitrum.io/rpc",
        rootRelayAddress: process.env.ARBITRUM_ROOT_RELAY ?? "",
      },
      {
        name: "Polygon Amoy",
        chainId: 80002,
        rpcUrl:
          process.env.POLYGON_RPC_URL ?? "https://rpc-amoy.polygon.technology",
        rootRelayAddress: process.env.POLYGON_ROOT_RELAY ?? "",
      },
    ],
  };

  if (!config.privateKey) {
    console.error("RELAYER_PRIVATE_KEY env var required");
    process.exit(1);
  }

  startRelayer(config).catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}