// Core types
export type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  DelegationResult,
  DelegateeMerkleProof,
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

// Handshake (v0.2 — real proof generation via snarkjs / rapidsnark)
export { proveHandshake, verifyHandshake } from './handshake';

// Prover backend (v0.4 — rapidsnark for sub-200ms proofs)
export { proveGroth16, activeProverBackend } from './prover';
export type { ProverBackend } from './prover';

// Off-chain verification (v0.3 — batch mode, ~100x gas reduction)
export {
  verifyHandshakeOffchain,
  OffchainVerificationBatch,
  postBatchRoot,
  computeSessionCommitment,
  verifyMerkleInclusion,
} from './offchain';

// Delegation (v0.3 — scope-narrowing one-way delegation, chain-linked on-chain)
export { delegate, verifyDelegation } from './delegation';
export type { DelegateInput } from './delegation';

// Poseidon hashes (exposed for chain-link verification in integrations)
export { poseidon2, poseidon3, poseidon4 } from './utils';

// Dev mode (v0.4 — test identities without circuit artifacts)
export { createDevIdentities } from './dev';
export type { DevIdentities, DevIdentityOptions } from './dev';

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
