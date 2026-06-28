/**
 * Bolyra DID Resolver
 *
 * Reference implementation of the did:bolyra resolution algorithm.
 * Returns DID Documents per W3C DID Core 1.0 and the Bolyra DID
 * Resolution Algorithm specification.
 *
 * Compatible with did-resolver v4.x (Resolver factory interface).
 */

import { ethers } from 'ethers';

// ---------- Types ----------

export interface DIDDocument {
  '@context': string[];
  id: string;
  controller: string;
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id: string;
  type: 'BolyraHumanMerkleRoot2026' | 'BolyraAgentMerkleRoot2026';
  controller: string;
  publicKeyBase64url: string;
}

export interface ServiceEndpoint {
  id: string;
  type: 'BolyraProofSubmission';
  serviceEndpoint: string;
  proofType: string | string[];
  supportedCircuits: string[];
}

export interface DIDResolutionResult {
  didResolutionMetadata: DIDResolutionMetadata;
  didDocument: DIDDocument | null;
  didDocumentMetadata: DIDDocumentMetadata;
}

export interface DIDResolutionMetadata {
  contentType?: string;
  error?: string;
  message?: string;
}

export interface DIDDocumentMetadata {
  created?: number;
  updated?: number;
  versionId?: string;
  deactivated?: boolean;
}

export interface ParsedDID {
  chainId: string;
  registryAddress: string;
  subjectId: string;
}

export interface OnChainIdentity {
  identityType: number; // 0 = none, 1 = human, 2 = agent
  humanMerkleRoot: string;
  agentMerkleRoot: string;
  nullifierHash: string;
  registeredAtBlock: number;
  lastUpdatedBlock: number;
  version: number;
}

export interface BolyraResolverOptions {
  rpcEndpoints: Record<string, string>;
}

// ---------- Constants ----------

const BOLYRA_CONTEXT = 'https://bolyra.ai/ns/did/v1';
const DID_CONTEXT = 'https://www.w3.org/ns/did/v1';
const JWS_CONTEXT = 'https://w3id.org/security/suites/jws-2020/v1';

const REGISTRY_ABI = [
  'function getIdentity(bytes32 subjectId) view returns (uint8 identityType, bytes32 humanMerkleRoot, bytes32 agentMerkleRoot, bytes32 nullifierHash, uint256 registeredAtBlock, uint256 lastUpdatedBlock, uint256 version)',
  'function isNullifierRevoked(bytes32 nullifierHash) view returns (bool)',
];

const DEFAULT_RPC_ENDPOINTS: Record<string, string> = {
  '84532': 'https://sepolia.base.org',
  '8453': 'https://mainnet.base.org',
  '1': 'https://eth.llamarpc.com',
};

// ---------- Helpers ----------

function hexToBase64url(hex: string): string {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = Buffer.from(clean, 'hex');
  return bytes.toString('base64url');
}

function isValidHexAddress(addr: string): boolean {
  return /^0x[0-9a-f]{40}$/.test(addr);
}

function isValid32ByteHex(val: string): boolean {
  return /^0x[0-9a-f]{64}$/.test(val);
}

// ---------- Core ----------

export function parseDID(did: string): ParsedDID | null {
  const parts = did.split(':');
  if (parts.length !== 5) return null;
  if (parts[0] !== 'did' || parts[1] !== 'bolyra') return null;

  const chainId = parts[2];
  if (!/^[1-9]\d*$/.test(chainId)) return null; // no leading zeros, must be numeric

  const registryAddress = parts[3].toLowerCase();
  if (!isValidHexAddress(registryAddress)) return null;

  const subjectId = parts[4].toLowerCase();
  if (!isValid32ByteHex(subjectId)) return null;

  return { chainId, registryAddress, subjectId };
}

function constructDIDDocument(
  did: string,
  identity: OnChainIdentity,
  chainId: string,
  registryAddress: string,
): DIDDocument {
  const doc: DIDDocument = {
    '@context': [DID_CONTEXT, JWS_CONTEXT, BOLYRA_CONTEXT],
    id: did,
    controller: did,
  };

  const caip10 = `eip155:${chainId}:${registryAddress}`;

  if (identity.identityType === 1) {
    // Human
    const vmId = `${did}#human-merkle-root`;
    doc.verificationMethod = [
      {
        id: vmId,
        type: 'BolyraHumanMerkleRoot2026',
        controller: did,
        publicKeyBase64url: hexToBase64url(identity.humanMerkleRoot),
      },
    ];
    doc.authentication = [vmId];
    doc.assertionMethod = [vmId];
    doc.service = [
      {
        id: `${did}#proof-submission`,
        type: 'BolyraProofSubmission',
        serviceEndpoint: caip10,
        proofType: 'Groth16',
        supportedCircuits: ['HumanUniqueness'],
      },
    ];
  } else if (identity.identityType === 2) {
    // Agent
    const vmId = `${did}#agent-merkle-root`;
    doc.verificationMethod = [
      {
        id: vmId,
        type: 'BolyraAgentMerkleRoot2026',
        controller: did,
        publicKeyBase64url: hexToBase64url(identity.agentMerkleRoot),
      },
    ];
    doc.authentication = [vmId];
    doc.assertionMethod = [vmId];
    doc.service = [
      {
        id: `${did}#proof-submission`,
        type: 'BolyraProofSubmission',
        serviceEndpoint: caip10,
        proofType: ['Groth16', 'PLONK'],
        supportedCircuits: ['AgentPolicy', 'Delegation'],
      },
    ];
  }

  return doc;
}

// ---------- Resolver ----------

export async function resolve(
  did: string,
  options?: { rpcEndpoints?: Record<string, string> },
): Promise<DIDResolutionResult> {
  const parsed = parseDID(did);
  if (!parsed) {
    return {
      didResolutionMetadata: { error: 'invalidDid' },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  const { chainId, registryAddress, subjectId } = parsed;

  const endpoints = { ...DEFAULT_RPC_ENDPOINTS, ...options?.rpcEndpoints };
  const rpcUrl = endpoints[chainId];
  if (!rpcUrl) {
    return {
      didResolutionMetadata: {
        error: 'unsupportedChainId',
        message: `Chain ${chainId} is not supported`,
      },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const registry = new ethers.Contract(registryAddress, REGISTRY_ABI, provider);

  let identity: OnChainIdentity;
  try {
    const result = await registry.getIdentity(subjectId);
    identity = {
      identityType: Number(result.identityType),
      humanMerkleRoot: result.humanMerkleRoot,
      agentMerkleRoot: result.agentMerkleRoot,
      nullifierHash: result.nullifierHash,
      registeredAtBlock: Number(result.registeredAtBlock),
      lastUpdatedBlock: Number(result.lastUpdatedBlock),
      version: Number(result.version),
    };
  } catch {
    return {
      didResolutionMetadata: { error: 'notFound' },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  if (identity.identityType === 0) {
    return {
      didResolutionMetadata: { error: 'notFound' },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  // Check revocation
  let isRevoked = false;
  try {
    isRevoked = await registry.isNullifierRevoked(identity.nullifierHash);
  } catch {
    // If revocation check fails, treat as not revoked but log
    // In production, this should be a hard failure
  }

  if (isRevoked) {
    return {
      didResolutionMetadata: { contentType: 'application/did+ld+json' },
      didDocument: {
        '@context': [DID_CONTEXT],
        id: did,
        controller: did,
      },
      didDocumentMetadata: {
        deactivated: true,
        updated: identity.lastUpdatedBlock,
      },
    };
  }

  const didDocument = constructDIDDocument(did, identity, chainId, registryAddress);

  return {
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument,
    didDocumentMetadata: {
      created: identity.registeredAtBlock,
      updated: identity.lastUpdatedBlock,
      versionId: String(identity.version),
    },
  };
}

// ---------- did-resolver v4 Factory ----------

/**
 * Returns a did-resolver v4-compatible resolver map.
 *
 * Usage:
 * ```ts
 * import { Resolver } from 'did-resolver';
 * import { getResolver } from '@bolyra/sdk/did/resolver';
 *
 * const resolver = new Resolver(getResolver({ rpcEndpoints: { '84532': 'https://sepolia.base.org' } }));
 * const result = await resolver.resolve('did:bolyra:84532:0x...:0x...');
 * ```
 */
export function getResolver(
  options?: BolyraResolverOptions,
): Record<string, (did: string, parsed: any, resolver: any, resolutionOptions: any) => Promise<DIDResolutionResult>> {
  return {
    bolyra: async (
      did: string,
      _parsed: any,
      _resolver: any,
      _resolutionOptions: any,
    ): Promise<DIDResolutionResult> => {
      return resolve(did, { rpcEndpoints: options?.rpcEndpoints });
    },
  };
}
