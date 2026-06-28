/**
 * @bolyra/sdk — public API surface
 */

// Existing exports (preserved)
export { createHumanIdentity } from './human.js';
export { createAgentCredential } from './agent.js';
export { proveHandshake, verifyHandshake } from './handshake.js';

// Envelope exports
export {
  ENVELOPE_VERSION,
  encode,
  decode,
  fromRaw,
  EnvelopeVersionError,
  UnknownCircuitError,
  SignalCountMismatch,
  InvalidProvingSystemError,
} from './envelope.js';

export type {
  BolyraEnvelope,
  DecodedEnvelope,
  SnarkProof,
  CircuitName,
  ProvingSystem,
} from './envelope.js';

// Signal maps
export {
  HUMAN_UNIQUENESS_SIGNALS,
  AGENT_POLICY_SIGNALS,
  DELEGATION_SIGNALS,
  SIGNAL_MAPS,
  VALID_PROVING_SYSTEMS,
} from './circuits/signal-maps.js';
