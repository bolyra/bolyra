// =============================================================
// @bolyra/sdk — public API (v0.3.0)
// =============================================================

// Low-level proving/verification (existing API — unchanged)
export {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from './prove';

// High-level client (new in v0.3.0)
export { BolyraClient } from './client';
export type {
  BolyraClientOptions,
  AgentCredentialInput,
  HandshakeResult,
} from './client';

// Artifact resolution
export { ArtifactResolver, ArtifactNotFoundError } from './artifacts';
export type { ResolvedArtifacts } from './artifacts';

// Merkle proof fetching
export { MerkleProofFetcher } from './merkle';
export type {
  MerkleProof,
  ProviderLike,
  EthersProvider,
  ViemPublicClient,
} from './merkle';

// Session nonce
export { generateSessionNonce } from './nonce';
export type { SessionNonce } from './nonce';
