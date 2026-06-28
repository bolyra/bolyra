/**
 * DID Document builder for did:bolyra identifiers.
 *
 * Provides typed constructors for verification methods, service endpoints,
 * and full DID Document assembly for both human and agent subjects.
 *
 * @module didDocument
 */

// --- Types ---

export interface BabyJubjubJwk {
  kty: "OKP";
  crv: "Baby-Jubjub";
  x: string; // base64url-encoded x coordinate
  y: string; // base64url-encoded y coordinate
}

export interface AgentVerificationMethod {
  id: string;
  type: "JsonWebKey2020";
  controller: string;
  publicKeyJwk: BabyJubjubJwk;
}

export interface HumanVerificationMethod {
  id: string;
  type: "BolyraZkpAuthentication2024";
  controller: string;
  nullifierCommitment: string;
  proofPurpose: "authentication";
  merkleTreeDepth: number;
}

export type BolyraVerificationMethod =
  | AgentVerificationMethod
  | HumanVerificationMethod;

export interface RegistryServiceEndpoint {
  registryAddress: string;
  chainId: number;
  chainName: string;
}

export interface BolyraService {
  id: string;
  type: "BolyraRegistryService";
  serviceEndpoint: RegistryServiceEndpoint;
}

export interface BolyraDidDocument {
  "@context": string[];
  id: string;
  controller: string;
  verificationMethod: BolyraVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service: BolyraService[];
}

export interface DIDDocumentMetadata {
  created?: string;
  updated?: string;
  versionId?: string;
  deactivated?: boolean;
}

export interface DIDResolutionMetadata {
  contentType?: string;
  error?: "invalidDid" | "notFound" | "deactivated" | "methodNotSupported";
}

export interface DIDResolutionResult {
  didDocument: BolyraDidDocument | null;
  didDocumentMetadata: DIDDocumentMetadata;
  didResolutionMetadata: DIDResolutionMetadata;
}

// --- Constants ---

export const BOLYRA_DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/jws-2020/v1",
  "https://bolyra.ai/ns/did/v1",
] as const;

export const SEMAPHORE_TREE_DEPTH = 20;

// --- Helpers ---

/**
 * Encode a 32-byte coordinate buffer as base64url (no padding).
 */
export function toBase64Url(buf: Uint8Array): string {
  const base64 = Buffer.from(buf).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode a base64url string back to a Buffer.
 */
export function fromBase64Url(s: string): Buffer {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64");
}

// --- Builders ---

/**
 * Build an AgentVerificationMethod from Baby Jubjub public key coordinates.
 *
 * @param did        - The full DID string
 * @param pubKeyX    - 32-byte x coordinate
 * @param pubKeyY    - 32-byte y coordinate
 */
export function buildAgentVerificationMethod(
  did: string,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array
): AgentVerificationMethod {
  return {
    id: `${did}#agent-key-1`,
    type: "JsonWebKey2020",
    controller: did,
    publicKeyJwk: {
      kty: "OKP",
      crv: "Baby-Jubjub",
      x: toBase64Url(pubKeyX),
      y: toBase64Url(pubKeyY),
    },
  };
}

/**
 * Build a HumanVerificationMethod from the nullifier commitment.
 *
 * @param did             - The full DID string
 * @param commitmentHex   - 64-char lowercase hex commitment
 */
export function buildHumanVerificationMethod(
  did: string,
  commitmentHex: string
): HumanVerificationMethod {
  return {
    id: `${did}#human-auth-1`,
    type: "BolyraZkpAuthentication2024",
    controller: did,
    nullifierCommitment: commitmentHex,
    proofPurpose: "authentication",
    merkleTreeDepth: SEMAPHORE_TREE_DEPTH,
  };
}

/**
 * Build a BolyraRegistryService endpoint.
 *
 * @param did              - The full DID string
 * @param registryAddress  - Contract address (0x-prefixed)
 * @param chainId          - EVM chain ID
 * @param chainName        - Human-readable chain name
 */
export function buildRegistryService(
  did: string,
  registryAddress: string,
  chainId: number,
  chainName: string
): BolyraService {
  return {
    id: `${did}#registry`,
    type: "BolyraRegistryService",
    serviceEndpoint: {
      registryAddress,
      chainId,
      chainName,
    },
  };
}

/**
 * Assemble a full DID Document for an agent subject.
 */
export function buildAgentDidDocument(
  did: string,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
  registryAddress: string,
  chainId: number,
  chainName: string
): BolyraDidDocument {
  const vm = buildAgentVerificationMethod(did, pubKeyX, pubKeyY);
  const svc = buildRegistryService(did, registryAddress, chainId, chainName);

  return {
    "@context": [...BOLYRA_DID_CONTEXT],
    id: did,
    controller: did,
    verificationMethod: [vm],
    authentication: [vm.id],
    assertionMethod: [vm.id],
    service: [svc],
  };
}

/**
 * Assemble a full DID Document for a human subject.
 */
export function buildHumanDidDocument(
  did: string,
  commitmentHex: string,
  registryAddress: string,
  chainId: number,
  chainName: string
): BolyraDidDocument {
  const vm = buildHumanVerificationMethod(did, commitmentHex);
  const svc = buildRegistryService(did, registryAddress, chainId, chainName);

  return {
    "@context": [...BOLYRA_DID_CONTEXT],
    id: did,
    controller: did,
    verificationMethod: [vm],
    authentication: [vm.id],
    assertionMethod: [],
    service: [svc],
  };
}

/**
 * Create an error resolution result.
 */
export function errorResult(
  error: DIDResolutionMetadata["error"]
): DIDResolutionResult {
  return {
    didDocument: null,
    didDocumentMetadata: error === "deactivated" ? { deactivated: true } : {},
    didResolutionMetadata: { error: error! },
  };
}
