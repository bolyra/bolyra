// =============================================================
// @bolyra/sdk — public API
// =============================================================

// Core proving / verification
export {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from './core/index.js';

// Session tokens (SD-JWT, off-chain proof reuse)
export {
  SessionTokenIssuer,
  SessionTokenVerifier,
  SessionTokenExpiredError,
  SessionTokenInvalidError,
  SessionTokenClaimMissingError,
} from './session/index.js';
export type {
  SessionTokenPayload,
  SessionTokenOptions,
  SessionVerifyOptions,
} from './session/index.js';
