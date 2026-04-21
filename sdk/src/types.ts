/** EdDSA identity for a human participant */
export interface HumanIdentity {
  /** EdDSA secret scalar (KEEP PRIVATE) */
  secret: bigint;
  /** Baby Jubjub public key coordinates */
  publicKey: { x: bigint; y: bigint };
  /** Poseidon2(Ax, Ay) — leaf in humanTree */
  commitment: bigint;
}

/** AI agent credential */
export interface AgentCredential {
  modelHash: bigint;
  operatorPublicKey: { x: bigint; y: bigint };
  permissionBitmask: bigint;
  expiryTimestamp: bigint;
  /** EdDSA signature of operator over credential commitment */
  signature: { R8: { x: bigint; y: bigint }; S: bigint };
  /** Poseidon5(modelHash, Ax, Ay, bitmask, expiry) — leaf in agentTree */
  commitment: bigint;
}

/** Permission bits (cumulative encoding) */
export enum Permission {
  READ_DATA = 0,
  WRITE_DATA = 1,
  FINANCIAL_SMALL = 2,     // < $100
  FINANCIAL_MEDIUM = 3,    // < $10,000 (implies SMALL)
  FINANCIAL_UNLIMITED = 4, // unlimited (implies MEDIUM + SMALL)
  SIGN_ON_BEHALF = 5,
  SUB_DELEGATE = 6,
  ACCESS_PII = 7,
}

/** Result of a mutual handshake verification */
export interface HandshakeResult {
  /** Human's nullifier (unique per scope) */
  humanNullifier: bigint;
  /** Agent's nullifier (unique per session) */
  agentNullifier: bigint;
  /** Session nonce used */
  sessionNonce: bigint;
  /** Agent's scope commitment (chain seed for delegation) */
  scopeCommitment: bigint;
  /** Whether the handshake was verified on-chain */
  verified: boolean;
}

/** Result of a delegation */
export interface DelegationResult {
  /** New scope commitment for the next hop */
  newScopeCommitment: bigint;
  /** Delegation nullifier (unique per delegation per session) */
  delegationNullifier: bigint;
  /** Hop number in the chain (0-indexed) */
  hopIndex: number;
}

/** Proof with public signals ready for on-chain verification */
export interface Proof {
  proof: any; // snarkjs proof object
  publicSignals: string[];
}

/** Result of an off-chain handshake verification (batched for later on-chain checkpoint) */
export interface OffchainVerificationResult extends HandshakeResult {
  /** Index of this session within the current batch */
  batchIndex: number;
  /** Merkle root of the batch at the time this result was added (undefined until batch is sealed) */
  batchRoot?: bigint;
}

/** On-chain checkpoint representing a batch of off-chain verified sessions */
export interface BatchCheckpoint {
  /** Poseidon Merkle root of all session commitments in the batch */
  root: bigint;
  /** Unix timestamp (seconds) when the batch was posted on-chain */
  timestamp: number;
  /** Number of sessions included in this batch */
  sessionCount: number;
}

/** Configuration for the SDK */
export interface BolyraConfig {
  /** RPC URL for the target chain (default: Base Sepolia) */
  rpcUrl?: string;
  /** Address of the IdentityRegistry contract */
  registryAddress?: string;
  /** Path to circuit WASM files (default: bundled) */
  circuitDir?: string;
  /** Path to zkey files (default: bundled) */
  zkeyDir?: string;
}
