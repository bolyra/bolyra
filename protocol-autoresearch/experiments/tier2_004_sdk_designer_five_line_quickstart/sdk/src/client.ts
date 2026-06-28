import { ArtifactResolver, ArtifactNotFoundError } from './artifacts';
import { MerkleProofFetcher, ProviderLike, MerkleProof } from './merkle';
import { generateSessionNonce, SessionNonce } from './nonce';

// These are the existing low-level SDK functions
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from './index';

/** Default HumanRegistry contract address on Base Sepolia. */
const DEFAULT_REGISTRY_ADDRESS = '0x0000000000000000000000000000000000000000'; // TODO: set after deploy

export interface BolyraClientOptions {
  /** ethers v6 Provider or viem PublicClient for on-chain Merkle lookups. */
  provider: ProviderLike;
  /** Override the default circuit artifacts directory. */
  artifactsDir?: string;
  /** Override the HumanRegistry contract address. */
  registryAddress?: string;
}

export interface AgentCredentialInput {
  modelHash: string;
  operatorPrivKey: string;
  permissions: number;
  expiry: number;
}

export interface HandshakeResult {
  verified: boolean;
  nullifierHash: string;
  sessionNonce: SessionNonce;
  humanProof: unknown;
  agentProof: unknown;
}

/**
 * High-level Bolyra client — orchestrates artifact resolution, Merkle
 * proof fetching, nonce generation, proving, and verification in a
 * single `handshake()` call.
 *
 * @example
 * ```ts
 * import { BolyraClient } from '@bolyra/sdk';
 * import { ethers } from 'ethers';
 *
 * const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
 * const client = new BolyraClient({ provider });
 * const result = await client.handshake(humanSecret, agentCred);
 * console.log(result.verified); // true
 * ```
 */
export class BolyraClient {
  private readonly artifactResolver: ArtifactResolver;
  private readonly merkleFetcher: MerkleProofFetcher;

  constructor(options: BolyraClientOptions) {
    this.artifactResolver = new ArtifactResolver(options.artifactsDir);
    this.merkleFetcher = new MerkleProofFetcher(
      options.provider,
      options.registryAddress ?? DEFAULT_REGISTRY_ADDRESS
    );
  }

  /**
   * Full handshake: prove human uniqueness + agent policy, then verify.
   *
   * @param humanSecret - The human's secret (used to derive identity commitment)
   * @param agentCredential - Agent credential parameters
   * @returns HandshakeResult with verification status, nullifier, and nonce
   */
  async handshake(
    humanSecret: string,
    agentCredential: AgentCredentialInput
  ): Promise<HandshakeResult> {
    // 1. Resolve circuit artifacts
    const artifacts = this.artifactResolver.resolve();

    // 2. Create identities from inputs
    const human = createHumanIdentity(humanSecret);
    const agent = createAgentCredential(
      agentCredential.modelHash,
      agentCredential.operatorPrivKey,
      agentCredential.permissions,
      agentCredential.expiry
    );

    // 3. Fetch Merkle proof from on-chain registry
    const merkleProof = await this.merkleFetcher.fetch(
      BigInt(human.identityCommitment)
    );

    // 4. Generate single-use session nonce
    const sessionNonce = generateSessionNonce();

    // 5. Prove handshake (human uniqueness + agent policy)
    const { humanProof, agentProof } = await proveHandshake(human, agent, {
      merkleProof: {
        root: merkleProof.root.toString(),
        siblings: merkleProof.siblings.map((s) => s.toString()),
        pathIndices: merkleProof.pathIndices,
      },
      sessionNonce: sessionNonce.toString('hex'),
      artifactPaths: {
        humanWasm: artifacts.humanWasm,
        humanZkey: artifacts.humanZkey,
        agentWasm: artifacts.agentWasm,
        agentZkey: artifacts.agentZkey,
      },
    });

    // 6. Verify the proofs
    const verified = await verifyHandshake(humanProof, agentProof, {
      sessionNonce: sessionNonce.toString('hex'),
      vkeyPaths: {
        humanVkey: artifacts.humanVkey,
        agentVkey: artifacts.agentVkey,
      },
    });

    return {
      verified,
      nullifierHash: humanProof.publicSignals?.nullifierHash ?? '',
      sessionNonce,
      humanProof,
      agentProof,
    };
  }
}
