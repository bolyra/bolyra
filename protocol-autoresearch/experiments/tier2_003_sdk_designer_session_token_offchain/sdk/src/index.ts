// =============================================================
// @bolyra/sdk — public API
// =============================================================

// Core proving / verification
export {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from './prove.js';

// Session tokens (SD-JWT, off-chain proof reuse)
export {
  issueSessionToken,
  verifySessionToken,
  BolyraSessionError,
} from './session.js';
export type {
  SessionClaims,
  SessionTokenOptions,
  VerifyTokenOptions,
  SessionErrorCode,
} from './session.js';
