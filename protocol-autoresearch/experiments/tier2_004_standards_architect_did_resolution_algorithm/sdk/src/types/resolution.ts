/**
 * Bolyra DID Resolution Types
 *
 * Aligned with W3C DID Core v1.0 and DID Resolution spec data model.
 * See spec/did-method-bolyra.md §7 for the resolution algorithm.
 */

// --- JsonWebKey2020 with BabyJubJub curve ---

export interface JsonWebKey2020 {
  /** Key type — always "OKP" for BabyJubJub */
  kty: 'OKP';
  /** Curve identifier — "BabyJubJub" (provisional, pending IANA registration) */
  crv: 'BabyJubJub';
  /** Base64url-encoded x-coordinate (big-endian, 32 bytes) */
  x: string;
  /** Base64url-encoded y-coordinate (big-endian, 32 bytes) */
  y: string;
}

// --- Verification Method ---

export interface VerificationMethod {
  id: string;
  type: 'JsonWebKey2020';
  controller: string;
  publicKeyJwk: JsonWebKey2020;
}

// --- Service Endpoints ---

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
  /** 8-bit cumulative permission mask (0–255). Present only for agent DIDs. */
  permissionMask?: number;
}

// --- DID Document ---

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  service?: ServiceEndpoint[];
}

// --- DID Resolution Metadata ---

export interface DIDResolutionMetadata {
  contentType?: string;
  error?: DIDResolutionError;
  message?: string;
  /** Advisory warning code (e.g. "staleRoot") */
  warning?: string;
}

export type DIDResolutionError =
  | 'invalidDid'
  | 'notFound'
  | 'deactivated'
  | 'methodNotSupported'
  | 'internalError';

// --- DID Document Metadata ---

export interface DIDDocumentMetadata {
  /** ISO 8601 timestamp of when the identity was created (enrollment block) */
  created?: string;
  /** ISO 8601 timestamp of the latest state change */
  updated?: string;
  /** True if the identity has been revoked */
  deactivated?: boolean;
  /** Hex-encoded Merkle root at resolution time — serves as ETag equivalent */
  versionId?: string;
  /** Equivalent DID identifiers */
  equivalentId?: string[];
  /** True if the Merkle root age exceeds the staleness threshold */
  staleRoot?: boolean;
}

// --- DID Resolution Result ---

export interface DIDResolutionResult {
  didDocument: DIDDocument | null;
  didResolutionMetadata: DIDResolutionMetadata;
  didDocumentMetadata: DIDDocumentMetadata;
}

// --- Resolution Options ---

export interface DIDResolutionOptions {
  /** Max age (seconds) of the Merkle root before surfacing staleRoot warning. Default: 3600 */
  stalenessThresholdSeconds?: number;
}
