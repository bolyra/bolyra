// =============================================================================
// @bolyra/sdk — public API
// =============================================================================

// --- Existing exports (preserve all prior public API) ---
export {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from './core.js';

export type { HumanIdentity, AgentCredential, HandshakeProof } from './types.js';

export { validateCumulativeBitEncoding } from './permissions.js';

// --- Envelope API (v0.3.0) ---
export {
  encode,
  decode,
  fromRaw,
  ENVELOPE_VERSION,
  EnvelopeError,
} from './envelope.js';

export type {
  BolyraEnvelope,
  NamedSignals,
  SnarkjsProof,
} from './envelope.js';

export { SIGNAL_MAPS, VALID_CIRCUITS, VALID_PROVING_SYSTEMS } from './signals.js';

export type { BolyraCircuit, BolyraProvingSystem } from './signals.js';
