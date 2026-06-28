/**
 * Session token error classes.
 * All extend BolyraError so existing catch blocks work.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export class BolyraError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'BolyraError';
    this.code = code;
  }
}

export class SessionTokenExpiredError extends BolyraError {
  constructor(message = 'Session token has expired') {
    super('SESSION_TOKEN_EXPIRED', message);
    this.name = 'SessionTokenExpiredError';
  }
}

export class SessionTokenInvalidError extends BolyraError {
  constructor(message = 'Session token is invalid') {
    super('SESSION_TOKEN_INVALID', message);
    this.name = 'SessionTokenInvalidError';
  }
}

export class SessionTokenClaimMissingError extends BolyraError {
  public readonly claimName: string;
  constructor(claimName: string) {
    super(
      'SESSION_TOKEN_CLAIM_MISSING',
      `Required claim '${claimName}' was not disclosed`,
    );
    this.name = 'SessionTokenClaimMissingError';
    this.claimName = claimName;
  }
}
