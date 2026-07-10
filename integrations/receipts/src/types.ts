export interface ReceiptPayload {
  v: 1;
  kind: 'bolyra.auth' | 'bolyra.commerce';
  /** Unix seconds when the decision was made. */
  issuedAt: number;
  /** Server identifier. */
  issuer: string;
  /** Signing key identifier for rotation. */
  keyId: string;

  subject: {
    /** Root credential DID. */
    rootDid: string;
    /** Acting agent DID (leaf of delegation chain, or root if no chain). */
    actingDid: string;
    credentialCommitment: string;
    effectiveCommitment: string;
  };

  decision: {
    allowed: boolean;
    reasonCode?: string;
    score: number;
    /** Decimal string to avoid BigInt serialization issues. */
    permissionBitmask: string;
    chainDepth: number;
  };

  proof: {
    bundleVersion: 1 | 2;
    /** Decimal string. */
    nonce: string;
    /** SHA-256 of canonical JSON of humanProof.proof. */
    humanProofHash: string;
    /** SHA-256 of canonical JSON of agentProof.proof. */
    agentProofHash: string;
    /** SHA-256 of canonical JSON of all public signals (human + agent). */
    publicSignalsHash: string;
    /** SHA-256 of canonical JSON of delegationChain (if v=2). */
    delegationChainHash?: string;
  };

  /** Present only when kind === 'bolyra.commerce'. */
  commerce?: CommerceFields;
}

export interface SignedReceipt {
  /** First 16 hex chars of payloadHash. */
  id: string;
  payload: ReceiptPayload;
  signature: {
    alg: 'ES256K';
    keyId: string;
    /** Ethereum address of the signer (hex, 0x-prefixed). */
    signer: string;
    /** keccak256 of canonical JSON payload (hex, 0x-prefixed). */
    payloadHash: string;
    /** r (32 bytes) + s (32 bytes) + v (1 byte) = 65 bytes (hex). */
    value: string;
  };
}

export interface ReceiptSignerConfig {
  issuer: string;
  keyId: string;
  /** secp256k1 private key, 32 bytes, hex-encoded, 0x-prefixed. */
  privateKey: string;
}

export interface CommerceFields {
  rail: string;
  amount: number;
  currency: string;
  merchant: string;
  intentHash: string;
}

export interface AuthReceiptInput {
  /** From BolyraAuthContext or equivalent. */
  rootDid: string;
  actingDid: string;
  credentialCommitment: string;
  effectiveCommitment: string;
  allowed: boolean;
  reasonCode?: string;
  score: number;
  permissionBitmask: string;
  chainDepth: number;
  /** Raw proof bundle for hashing. */
  humanProof: { proof: unknown };
  agentProof: { proof: unknown };
  humanPublicSignals: string[];
  agentPublicSignals: string[];
  bundleVersion: 1 | 2;
  nonce: string;
  delegationChain?: unknown[];
}

export interface CommerceReceiptInput extends AuthReceiptInput {
  commerce: CommerceFields;
}
