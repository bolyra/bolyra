/**
 * Bolyra SDK type definitions.
 * Schema version: 3 (breaking change: added blindingSalt to AgentCredential)
 */

export const SCHEMA_VERSION = 3;

// --- Permission bitmask constants ---
export const Permission = {
  READ_DATA:           0b00000001, // bit 0
  WRITE_DATA:          0b00000010, // bit 1
  FINANCIAL_SMALL:     0b00000100, // bit 2: < $100
  FINANCIAL_MEDIUM:    0b00001100, // bit 3: < $10K (implies bit 2)
  FINANCIAL_UNLIMITED: 0b00011100, // bit 4: implies bits 2+3
  SIGN_ON_BEHALF:      0b00100000, // bit 5
  SUB_DELEGATE:        0b01000000, // bit 6
  ACCESS_PII:          0b10000000, // bit 7
} as const;

export type PermissionBitmask = number;

/**
 * Validates cumulative-bit encoding rules:
 * - FINANCIAL_MEDIUM (bit 3) implies FINANCIAL_SMALL (bit 2)
 * - FINANCIAL_UNLIMITED (bit 4) implies FINANCIAL_MEDIUM (bit 3) and FINANCIAL_SMALL (bit 2)
 */
export function validateCumulativeBitEncoding(bitmask: number): boolean {
  if (bitmask < 0 || bitmask > 255) return false;
  // bit 3 set => bit 2 must be set
  if ((bitmask & 0b00001000) && !(bitmask & 0b00000100)) return false;
  // bit 4 set => bits 3 and 2 must be set
  if ((bitmask & 0b00010000) && !(bitmask & 0b00001000)) return false;
  if ((bitmask & 0b00010000) && !(bitmask & 0b00000100)) return false;
  return true;
}

// --- Identity types ---

export interface HumanIdentity {
  readonly secret: bigint;
  readonly identityCommitment: bigint;
  readonly nullifier: bigint;
}

export interface AgentCredential {
  readonly modelHash: bigint;
  readonly operatorPubKeyX: bigint;
  readonly operatorPubKeyY: bigint;
  readonly operatorPrivKey: bigint;
  readonly permissionBitmask: number;
  readonly expiry: bigint;
  readonly credentialCommitment: bigint;
  readonly blindingSalt: bigint; // NEW (v3): CSPRNG-generated 254-bit blinding salt
  readonly sigR8x: bigint;
  readonly sigR8y: bigint;
  readonly sigS: bigint;
}

export interface DelegatedCredential {
  readonly parentCredential: AgentCredential;
  readonly delegatedPermissionBitmask: number;
  readonly delegatedCredentialCommitment: bigint;
  readonly delegatedBlindingSalt: bigint; // NEW (v3): per-hop blinding salt
  readonly delegatorSecret: bigint;
  readonly delegationExpiry: bigint;
}

// --- Proof types ---

export interface Groth16Proof {
  readonly pi_a: [bigint, bigint];
  readonly pi_b: [[bigint, bigint], [bigint, bigint]];
  readonly pi_c: [bigint, bigint];
  readonly protocol: 'groth16';
}

export interface PlonkProof {
  readonly protocol: 'plonk';
  readonly [key: string]: unknown;
}

export type ZKProof = Groth16Proof | PlonkProof;

export interface HandshakeProof {
  readonly proof: ZKProof;
  readonly publicSignals: bigint[];
}

export interface AgentHandshakeResult {
  readonly proof: ZKProof;
  readonly credentialCommitment: bigint;
  readonly scopeCommitment: bigint;
  readonly nonceBinding: bigint;
}

export interface DelegationProofResult {
  readonly proof: ZKProof;
  readonly parentScopeCommitment: bigint;
  readonly delegatedScopeCommitment: bigint;
  readonly delegationBinding: bigint;
}
