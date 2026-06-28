/**
 * Bolyra DID Resolver
 *
 * Implements the did:bolyra resolution algorithm per spec/did-resolution-algorithm.md.
 * Queries IdentityRegistry.sol on-chain state and constructs W3C DID Core compliant
 * DID Documents.
 */

import { ethers } from 'ethers';

// --- Types ---

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
  permissions?: number;
}

export interface DIDDocumentMetadata {
  created?: string;
  updated?: string;
  versionId?: string;
  deactivated?: boolean;
}

export interface DIDResolutionMetadata {
  contentType?: string;
  error?: string;
  message?: string;
}

export interface DIDResolutionResult {
  didDocument: DIDDocument | null;
  didResolutionMetadata: DIDResolutionMetadata;
  didDocumentMetadata: DIDDocumentMetadata;
}

export type DIDResolutionError =
  | 'invalidDid'
  | 'notFound'
  | 'deactivated'
  | 'methodNotSupported'
  | 'internalError';

// --- ABI fragment for IIdentityRegistry ---

const REGISTRY_ABI = [
  'function getEnrollmentStatus(bytes32 commitment) view returns (tuple(bool enrolled, uint256[2] publicKey, uint256 blockNumber))',
  'function getMerkleRoot() view returns (uint256)',
  'function isRevoked(bytes32 commitment) view returns (bool)',
  'function getAgentCredential(bytes32 commitment) view returns (tuple(bytes32 agentId, bytes32 modelHash, uint256[2] operatorPubKey, uint8 permissions, uint256 expiry))',
];

const DID_PREFIX = 'did:bolyra:';
const ZERO_BYTES32 = '0x' + '0'.repeat(64);

// --- Helpers ---

function parseDID(did: string): { commitment: string } | { error: DIDResolutionError; message: string } {
  if (!did.startsWith(DID_PREFIX)) {
    return { error: 'invalidDid', message: 'Missing did:bolyra: prefix' };
  }

  let identifier = did.substring(DID_PREFIX.length);
  identifier = identifier.replace(/^0x/i, '').toLowerCase();

  if (!/^[0-9a-f]{1,64}$/.test(identifier)) {
    return { error: 'invalidDid', message: 'Invalid hex commitment' };
  }

  const commitment = '0x' + identifier.padStart(64, '0');
  return { commitment };
}

/**
 * Encode a BabyJubJub public key point as multibase (base58btc).
 *
 * Compression: store x-coordinate (32 bytes) with parity bit of y in the high bit.
 * Multicodec prefix: 0xed 0x01 (EdDSA public key).
 * Then base58btc encode and prepend 'z'.
 */
export function encodeBabyJubJubMultibase(pubKey: [bigint, bigint]): string {
  const [x, y] = pubKey;

  // Compress: 32-byte x with parity of y in high bit
  const xBytes = Buffer.alloc(32);
  let xVal = x;
  for (let i = 31; i >= 0; i--) {
    xBytes[i] = Number(xVal & 0xffn);
    xVal >>= 8n;
  }
  if (y & 1n) {
    xBytes[0] |= 0x80;
  }

  // Multicodec prefix for EdDSA: 0xed 0x01
  const prefixed = Buffer.concat([Buffer.from([0xed, 0x01]), xBytes]);

  // base58btc encode
  return 'z' + base58btcEncode(prefixed);
}

/** Minimal base58btc encoder (Bitcoin alphabet). */
function base58btcEncode(data: Buffer): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + data.toString('hex'));
  const chars: string[] = [];
  while (num > 0n) {
    const [q, r] = [num / 58n, num % 58n];
    chars.unshift(ALPHABET[Number(r)]);
    num = q;
  }
  // Leading zeros
  for (const byte of data) {
    if (byte === 0) chars.unshift('1');
    else break;
  }
  return chars.join('');
}

// --- Resolver ---

export class DIDResolver {
  private registry: ethers.Contract;
  private provider: ethers.Provider;

  constructor(provider: ethers.Provider, registryAddress: string) {
    this.provider = provider;
    this.registry = new ethers.Contract(registryAddress, REGISTRY_ABI, provider);
  }

  /**
   * Resolve a did:bolyra DID to a DIDResolutionResult.
   *
   * Implements the three-phase pipeline from spec/did-resolution-algorithm.md:
   *   Phase 1: Parse DID string
   *   Phase 2: Query on-chain state (batched via Promise.all)
   *   Phase 3: Construct DID Document
   */
  async resolve(did: string): Promise<DIDResolutionResult> {
    // Phase 1: Parse
    const parsed = parseDID(did);
    if ('error' in parsed) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: parsed.error, message: parsed.message },
        didDocumentMetadata: {},
      };
    }

    const { commitment } = parsed;

    // Phase 2: On-chain query (batched)
    let enrollmentStatus: {
      enrolled: boolean;
      publicKey: [bigint, bigint];
      blockNumber: bigint;
    };
    let isRevoked: boolean;
    let agentCred: {
      agentId: string;
      modelHash: string;
      operatorPubKey: [bigint, bigint];
      permissions: number;
      expiry: bigint;
    };
    let merkleRoot: bigint;

    try {
      [enrollmentStatus, isRevoked, agentCred, merkleRoot] = await Promise.all([
        this.registry.getEnrollmentStatus(commitment),
        this.registry.isRevoked(commitment),
        this.registry.getAgentCredential(commitment),
        this.registry.getMerkleRoot(),
      ]);
    } catch (err) {
      return {
        didDocument: null,
        didResolutionMetadata: {
          error: 'internalError',
          message: err instanceof Error ? err.message : 'RPC query failed',
        },
        didDocumentMetadata: {},
      };
    }

    // Phase 3: State interpretation
    const agentIdIsZero = agentCred.agentId === ZERO_BYTES32;

    if (!enrollmentStatus.enrolled && agentIdIsZero) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'notFound', message: 'Commitment not enrolled' },
        didDocumentMetadata: {},
      };
    }

    if (isRevoked) {
      return {
        didDocument: {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
        },
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
        didDocumentMetadata: { deactivated: true },
      };
    }

    // Determine identity type and public key
    const isAgent = !agentIdIsZero;
    const pubKey: [bigint, bigint] = isAgent
      ? agentCred.operatorPubKey
      : enrollmentStatus.publicKey;

    const publicKeyMultibase = encodeBabyJubJubMultibase(pubKey);

    // Build DID Document
    const verificationMethod: VerificationMethod = {
      id: `${did}#key-1`,
      type: 'EdDSAVerificationKey2022',
      controller: did,
      publicKeyMultibase,
    };

    const services: ServiceEndpoint[] = [
      {
        id: `${did}#proof-exchange`,
        type: 'BolyraProofExchange',
        serviceEndpoint: 'https://relay.bolyra.ai/exchange',
      },
    ];

    if (isAgent) {
      services.push({
        id: `${did}#agent-policy`,
        type: 'BolyraAgentPolicy',
        serviceEndpoint: 'https://relay.bolyra.ai/agent/policy',
        permissions: agentCred.permissions,
      });
    }

    const didDocument: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/eddsa-2022/v1',
        'https://bolyra.ai/ns/v1',
      ],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`],
      service: services,
    };

    const merkleRootHex = '0x' + merkleRoot.toString(16).padStart(64, '0');

    const blockNumber = Number(enrollmentStatus.blockNumber || 0n);
    const block = blockNumber > 0 ? await this.provider.getBlock(blockNumber) : null;
    const timestamp = block
      ? new Date(block.timestamp * 1000).toISOString()
      : new Date().toISOString();

    return {
      didDocument,
      didResolutionMetadata: { contentType: 'application/did+ld+json' },
      didDocumentMetadata: {
        created: timestamp,
        updated: timestamp,
        versionId: merkleRootHex,
      },
    };
  }
}
