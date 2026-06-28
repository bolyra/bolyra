/**
 * MerkleProofFetcher — queries the on-chain HumanRegistry contract
 * to fetch the current Merkle root and sibling path for a given
 * identity commitment.
 *
 * Accepts either an ethers v6 Provider or a viem PublicClient.
 * Caches the root per block number to avoid redundant RPC calls.
 */

/** Minimal ethers v6 Provider interface (avoid importing ethers as a hard dep). */
export interface EthersProvider {
  call(tx: { to: string; data: string }): Promise<string>;
  getBlockNumber(): Promise<number>;
}

/** Minimal viem PublicClient interface. */
export interface ViemPublicClient {
  readContract(args: {
    address: `0x${string}`;
    abi: readonly unknown[];
    functionName: string;
    args?: readonly unknown[];
  }): Promise<unknown>;
  getBlockNumber(): Promise<bigint>;
}

export type ProviderLike = EthersProvider | ViemPublicClient;

export interface MerkleProof {
  root: bigint;
  siblings: bigint[];
  pathIndices: number[];
  leafIndex: number;
}

/** ABI fragment for HumanRegistry.getMerkleProof(uint256) */
const GET_MERKLE_PROOF_ABI = [
  {
    inputs: [{ name: 'identityCommitment', type: 'uint256' }],
    name: 'getMerkleProof',
    outputs: [
      { name: 'root', type: 'uint256' },
      { name: 'siblings', type: 'uint256[]' },
      { name: 'pathIndices', type: 'uint8[]' },
      { name: 'leafIndex', type: 'uint256' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
] as const;

function isViemClient(provider: ProviderLike): provider is ViemPublicClient {
  return 'readContract' in provider;
}

export class MerkleProofFetcher {
  private readonly provider: ProviderLike;
  private readonly registryAddress: string;
  private cache = new Map<number, Map<string, MerkleProof>>();

  constructor(provider: ProviderLike, registryAddress: string) {
    this.provider = provider;
    this.registryAddress = registryAddress;
  }

  async fetch(identityCommitment: bigint): Promise<MerkleProof> {
    const blockNumber = await this.getBlockNumber();
    const commitKey = identityCommitment.toString();

    const blockCache = this.cache.get(blockNumber);
    if (blockCache?.has(commitKey)) {
      return blockCache.get(commitKey)!;
    }

    const proof = await this.fetchFromChain(identityCommitment);

    // Evict previous blocks to avoid unbounded growth
    if (!this.cache.has(blockNumber)) {
      this.cache.clear();
      this.cache.set(blockNumber, new Map());
    }
    this.cache.get(blockNumber)!.set(commitKey, proof);

    return proof;
  }

  private async getBlockNumber(): Promise<number> {
    if (isViemClient(this.provider)) {
      return Number(await this.provider.getBlockNumber());
    }
    return this.provider.getBlockNumber();
  }

  private async fetchFromChain(identityCommitment: bigint): Promise<MerkleProof> {
    if (isViemClient(this.provider)) {
      const result = (await this.provider.readContract({
        address: this.registryAddress as `0x${string}`,
        abi: GET_MERKLE_PROOF_ABI,
        functionName: 'getMerkleProof',
        args: [identityCommitment],
      })) as [bigint, bigint[], number[], bigint];

      return {
        root: result[0],
        siblings: result[1],
        pathIndices: result[2],
        leafIndex: Number(result[3]),
      };
    }

    // ethers v6 path — manual ABI encoding
    const { ethers } = await import('ethers');
    const iface = new ethers.Interface(GET_MERKLE_PROOF_ABI);
    const data = iface.encodeFunctionData('getMerkleProof', [identityCommitment]);

    const raw = await this.provider.call({ to: this.registryAddress, data });

    const decoded = iface.decodeFunctionResult('getMerkleProof', raw);
    return {
      root: BigInt(decoded.root),
      siblings: decoded.siblings.map((s: unknown) => BigInt(s as string)),
      pathIndices: decoded.pathIndices.map((p: unknown) => Number(p)),
      leafIndex: Number(decoded.leafIndex),
    };
  }
}
