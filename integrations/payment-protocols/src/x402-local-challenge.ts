/**
 * Agent-side host: local challenge context (spec §4.2, "local mode").
 *
 * When the resource server does not participate in the profile (no
 * `x402-evc-nonce` / `x402-evc-expires`), a payer-side enforcement point
 * builds the challenge context itself from the raw x402 v2
 * `PAYMENT-REQUIRED` header. The nonce is the SHA-256 of the header value
 * exactly as received; the deadline here is PROVISIONAL (receipt time plus
 * the leg's timeout, capped by host policy) and is finalized against the
 * verified quote inside `verifyX402EvcAuthorization`.
 *
 * This helper SELECTS a leg. It does not check it. Only an allow decision
 * carries the checked leg.
 */
import { VerifyDenial } from '@bolyra/mpp';
import { createHash } from 'node:crypto';

import { isUnixSeconds, type X402EvcContext, type X402EvcRequirements } from './x402-evc';
import { isPlainObject } from './x402-issuer-quote/jws';

/** One x402 v2 `accepts[]` entry, as far as the profile reads it. */
export interface X402Leg {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

export interface X402LocalChallenge {
  mode: 'local';
  /** Unix seconds when the host received the challenge; never refreshed. */
  receivedAt: number;
  /** Provisional context: `expiresAt` is finalized against the verified quote. */
  context: X402EvcContext;
  requirements: X402EvcRequirements;
  /** Deep-frozen copy of `accepts[legIndex]`. Selected, not checked. */
  selectedLeg: Readonly<X402Leg>;
  /** Lowercase hex SHA-256 of the header value exactly as received. */
  headerSha256: string;
}

export interface X402LocalChallengeInput {
  /** The raw `PAYMENT-REQUIRED` header value (standard base64 of x402 v2 JSON). */
  headerValue: string;
  /** The exact outbound request URL the agent is about to pay for (host-known). */
  resource: string;
  /** Which `accepts[]` entry the host intends to pay. */
  legIndex: number;
  /** Host clock, unix seconds. */
  now: number;
  /** Host policy cap on the provisional deadline, seconds, 1..900. */
  maxSeconds: number;
}

export const MAX_PAYMENT_REQUIRED_CHARS = 64 * 1024;
export const MAX_LOCAL_CHALLENGE_SECONDS = 900;
const STANDARD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const FORBIDDEN_MEMBERS = ['__proto__', 'constructor', 'prototype'] as const;

function malformed(reason: string): VerifyDenial {
  return new VerifyDenial('malformed_input', 'x402 PAYMENT-REQUIRED challenge is not usable', { reason });
}

function hostFault(reason: string): VerifyDenial {
  return new VerifyDenial('internal_error', 'local challenge host input is invalid', { reason });
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const key of Object.keys(value as object)) deepFreeze((value as Record<string, unknown>)[key]);
    Object.freeze(value);
  }
  return value;
}

/** Structured clone restricted to JSON-shaped data, with prototype-named members rejected. */
function cloneJson(value: unknown, reason: string): unknown {
  if (Array.isArray(value)) return value.map((v) => cloneJson(v, reason));
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if ((FORBIDDEN_MEMBERS as readonly string[]).includes(key)) throw malformed(reason);
      out[key] = cloneJson(value[key], reason);
    }
    return out;
  }
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  throw malformed(reason);
}

function requireString(leg: Record<string, unknown>, field: string): string {
  const v = leg[field];
  if (typeof v !== 'string' || v.length === 0) throw malformed(`leg_${field}`);
  return v;
}

export function x402LocalChallenge(input: X402LocalChallengeInput): X402LocalChallenge {
  const { headerValue, resource, legIndex, now, maxSeconds } = input;
  if (typeof resource !== 'string' || resource.length === 0) throw hostFault('resource');
  if (!isUnixSeconds(now)) throw hostFault('now');
  if (!Number.isInteger(maxSeconds) || maxSeconds < 1 || maxSeconds > MAX_LOCAL_CHALLENGE_SECONDS) {
    throw hostFault('max_seconds');
  }

  if (typeof headerValue !== 'string') throw malformed('header_type');
  if (headerValue.length > MAX_PAYMENT_REQUIRED_CHARS) throw malformed('header_size');
  if (!STANDARD_BASE64.test(headerValue)) throw malformed('header_base64');
  const bytes = Buffer.from(headerValue, 'base64');
  if (bytes.toString('base64') !== headerValue) throw malformed('header_base64');

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw malformed('header_json');
  }
  if (!isPlainObject(parsed)) throw malformed('header_object');
  for (const name of FORBIDDEN_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(parsed, name)) throw malformed('header_object');
  }
  if (parsed.x402Version !== 2) throw malformed('x402_version');
  const accepts = parsed.accepts;
  if (!Array.isArray(accepts) || accepts.length === 0) throw malformed('accepts');
  if (!Number.isInteger(legIndex) || legIndex < 0 || legIndex >= accepts.length) throw malformed('leg_index');
  const rawLeg = accepts[legIndex];
  if (!isPlainObject(rawLeg)) throw malformed('leg_object');

  const timeout = rawLeg.maxTimeoutSeconds;
  if (typeof timeout !== 'number' || !Number.isInteger(timeout) || timeout <= 0) throw malformed('leg_max_timeout');
  const leg: X402Leg = {
    scheme: requireString(rawLeg, 'scheme'),
    network: requireString(rawLeg, 'network'),
    asset: requireString(rawLeg, 'asset'),
    amount: requireString(rawLeg, 'amount'),
    payTo: requireString(rawLeg, 'payTo'),
    maxTimeoutSeconds: timeout,
  };
  if ('extra' in rawLeg) {
    if (!isPlainObject(rawLeg.extra)) throw malformed('leg_extra');
    leg.extra = cloneJson(rawLeg.extra, 'leg_extra') as Record<string, unknown>;
  }
  deepFreeze(leg);

  const headerSha256 = createHash('sha256').update(headerValue, 'utf8').digest('hex');
  const requirements: X402EvcRequirements = {
    scheme: leg.scheme,
    network: leg.network,
    asset: leg.asset,
    amount: leg.amount,
    payTo: leg.payTo,
    ...(leg.extra !== undefined ? { extra: cloneJson(leg.extra, 'leg_extra') as Record<string, unknown> } : {}),
  };

  return {
    mode: 'local',
    receivedAt: now,
    headerSha256,
    selectedLeg: leg,
    requirements,
    context: {
      resource,
      requirements,
      nonce: headerSha256,
      expiresAt: now + Math.min(leg.maxTimeoutSeconds, maxSeconds),
    },
  };
}
