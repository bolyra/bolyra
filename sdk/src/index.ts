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
} from './identity';

// Handshake (stubs for v0.1, implemented in v0.2)
export { proveHandshake, verifyHandshake } from './handshake';

// Delegation (stubs for v0.1, implemented in v0.2)
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
} from './errors';
