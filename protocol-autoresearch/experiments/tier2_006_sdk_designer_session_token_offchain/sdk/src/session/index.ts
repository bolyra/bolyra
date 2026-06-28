/**
 * Session token module — SD-JWT off-chain proof reuse.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export { SessionTokenIssuer } from './SessionTokenIssuer.js';
export { SessionTokenVerifier } from './SessionTokenVerifier.js';
export {
  SessionTokenExpiredError,
  SessionTokenInvalidError,
  SessionTokenClaimMissingError,
} from './errors.js';
export type {
  SessionTokenPayload,
  SessionTokenOptions,
  SessionVerifyOptions,
  HandshakeResult,
} from './types.js';
