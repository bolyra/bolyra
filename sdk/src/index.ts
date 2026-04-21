// Core types
export type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  DelegationResult,
  Proof,
  BolyraConfig,
  OffchainVerificationResult,
  BatchCheckpoint,
} from './types';

// Permission enum
export { Permission } from './types';

// Identity creation
export {
  createHumanIdentity,
  createAgentCredential,
  permissionsToBitmask,
  validateCumulativeBitEncoding,
  validateHumanSecret,
  validateAgentExpiry,
  BN254_FIELD_ORDER,
} from './identity';

// Handshake (v0.2 — real proof generation via snarkjs)
export { proveHandshake, verifyHandshake } from './handshake';

// Off-chain verification (v0.3 — batch mode, ~100x gas reduction)
export {
  verifyHandshakeOffchain,
  OffchainVerificationBatch,
  postBatchRoot,
  computeSessionCommitment,
  verifyMerkleInclusion,
} from './offchain';

// Delegation (stubs — coming in v0.3)
export { delegate, verifyDelegation } from './delegation';

// Errors
export {
  BolyraError,
  ProofGenerationError,
  VerificationError,
  InvalidPermissionError,
  ExpiredCredentialError,
  ScopeEscalationError,
  StaleProofError,
  InvalidSecretError,
  CircuitArtifactNotFoundError,
  MerkleTreeError,
  ConfigurationError,
} from './errors';
