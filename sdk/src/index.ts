// Core types
export type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  DelegationResult,
  Proof,
  BolyraConfig,
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
