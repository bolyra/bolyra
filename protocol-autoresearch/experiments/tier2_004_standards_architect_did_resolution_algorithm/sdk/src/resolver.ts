/**
 * DID resolver for did:bolyra identifiers.
 *
 * Implements the resolve(did, options) interface compatible with the
 * did-resolver npm package and DIF Universal Resolver driver pattern.
 *
 * @module resolver
 */

import { ethers } from "ethers";
import {
  type BolyraDidDocument,
  type DIDDocumentMetadata,
  type DIDResolutionMetadata,
  type DIDResolutionResult,
  buildAgentDidDocument,
  buildHumanDidDocument,
  errorResult,
} from "./didDocument";

// --- Constants ---

const DID_REGEX = /^did:bolyra:([0-9a-f]{64})$/;

// Minimal ABI for IdentityRegistry.getRegistration()
const REGISTRY_ABI = [
  "function getRegistration(bytes32 commitment) external view returns (uint8 keyType, bytes publicKey, bytes32 merkleRoot, uint256 timestamp, bool active)",
];

// --- Types ---

export interface BolyraResolverOptions {
  /** Ethers provider or JSON-RPC URL */
  provider: ethers.Provider | string;
  /** IdentityRegistry contract address */
  registryAddress: string;
  /** EVM chain ID (default: 84532 for Base Sepolia) */
  chainId?: number;
  /** Human-readable chain name (default: "Base Sepolia") */
  chainName?: string;
}

export interface ResolutionOptions {
  accept?: string;
}

// --- Resolver ---

/**
 * Create a did:bolyra resolver function compatible with the did-resolver
 * npm package's Resolver class.
 *
 * Usage with did-resolver:
 * ```ts
 * import { Resolver } from "did-resolver";
 * import { getBolyraResolver } from "@bolyra/sdk/resolver";
 *
 * const resolver = new Resolver(getBolyraResolver({ provider, registryAddress }));
 * const result = await resolver.resolve("did:bolyra:<commitment>");
 * ```
 */
export function getBolyraResolver(options: BolyraResolverOptions): Record<string, (did: string, parsed: unknown, resolver: unknown, resOptions: ResolutionOptions) => Promise<DIDResolutionResult>> {
  return {
    bolyra: async (
      did: string,
      _parsed: unknown,
      _resolver: unknown,
      _resOptions: ResolutionOptions
    ) => {
      return resolve(did, options);
    },
  };
}

/**
 * Parse a did:bolyra DID string and extract the commitment hex.
 * Returns null if the DID is invalid.
 */
export function parseDid(did: string): string | null {
  const match = did.match(DID_REGEX);
  return match ? match[1] : null;
}

/**
 * Resolve a did:bolyra DID to a DID Document.
 *
 * Follows the W3C DID Core section 7.1 resolution algorithm as specified
 * in spec/did-resolution-algorithm.md.
 */
export async function resolve(
  did: string,
  options: BolyraResolverOptions
): Promise<DIDResolutionResult> {
  // Step 1-4: Parse and validate
  const commitmentHex = parseDid(did);
  if (!commitmentHex) {
    // Check if it's a different method
    if (did.startsWith("did:") && !did.startsWith("did:bolyra:")) {
      return errorResult("methodNotSupported");
    }
    return errorResult("invalidDid");
  }

  // Step 5: Query IdentityRegistry
  const provider =
    typeof options.provider === "string"
      ? new ethers.JsonRpcProvider(options.provider)
      : options.provider;

  const registry = new ethers.Contract(
    options.registryAddress,
    REGISTRY_ABI,
    provider
  );

  const commitment = "0x" + commitmentHex;

  let keyType: number;
  let publicKey: string;
  let merkleRoot: string;
  let timestamp: bigint;
  let active: boolean;

  try {
    [keyType, publicKey, merkleRoot, timestamp, active] =
      await registry.getRegistration(commitment);
  } catch {
    return errorResult("notFound");
  }

  // Step 6: Check existence
  if (timestamp === 0n) {
    return errorResult("notFound");
  }

  // Step 7: Check deactivation
  if (!active) {
    return errorResult("deactivated");
  }

  const chainId = options.chainId ?? 84532;
  const chainName = options.chainName ?? "Base Sepolia";

  // Step 8-9: Build DID Document based on subject type
  let didDocument: BolyraDidDocument;

  if (keyType === 0) {
    // Human
    didDocument = buildHumanDidDocument(
      did,
      commitmentHex,
      options.registryAddress,
      chainId,
      chainName
    );
  } else if (keyType === 1) {
    // Agent — decode 64-byte public key into x, y coordinates
    const pubKeyBytes = ethers.getBytes(publicKey);
    const pubKeyX = pubKeyBytes.slice(0, 32);
    const pubKeyY = pubKeyBytes.slice(32, 64);

    didDocument = buildAgentDidDocument(
      did,
      pubKeyX,
      pubKeyY,
      options.registryAddress,
      chainId,
      chainName
    );
  } else {
    return errorResult("invalidDid");
  }

  // Step 10: Populate metadata
  const createdDate = new Date(Number(timestamp) * 1000).toISOString();

  const didDocumentMetadata: DIDDocumentMetadata = {
    created: createdDate,
    updated: createdDate,
    deactivated: false,
  };

  const didResolutionMetadata: DIDResolutionMetadata = {
    contentType: "application/did+ld+json",
  };

  return {
    didDocument,
    didDocumentMetadata,
    didResolutionMetadata,
  };
}
