/**
 * Issuer-quoted payee binding (spec §4.2) for an agent-side host.
 *
 * When an x402 challenge names a placeholder `payTo` and carries an
 * issuer-signed quote token, the host can bind the payee to the QUOTE
 * ISSUER: the host `audience` (the merchant identity the operator's mandate
 * covers) must byte-equal the token's `iss`, the token must verify under an
 * out-of-band provisioned public key, and the price, product and every
 * settlement-consumed challenge field must equal the authenticated claims.
 *
 * What a successful binding proves: the holder of the issuer's key quoted
 * this product at this price within this window. What it does NOT prove:
 * ownership of any derived address, that the quote was addressed to this
 * host (`aud` is the settlement rail), who ultimately receives funds, or
 * delivery. Every failure denies `request_mismatch` with a stable
 * `detail.reason`; configuration faults reject at creation (`internal_error`).
 */
import { importJWK, type CryptoKey, type JWK } from 'jose';
import { VerifyDenial } from '@bolyra/mpp';

import { isUnixSeconds, type X402EvcContext, type X402EvcRequirements } from '../x402-evc';
import { JwsRejected, isPlainObject, peekHeader, verifyCompactEs, type JwsAlg } from './jws';

export type { JwsAlg } from './jws';

export interface PayeeBinding {
  kind: 'issuer_quote';
  issuer: string;
  kid: string;
  jti: string;
  exp: number;
  /**
   * Lowercase hex SHA-256 over the exact compact token (UTF-8 bytes). An
   * audit handle, NOT a unique quote identifier: ECDSA signatures are
   * malleable (high-S), so one quote can have several valid encodings.
   * Replay identity is `(issuer, jti)`.
   */
  token_sha256: string;
}

export interface PayeeResolution {
  binding: PayeeBinding;
  /** Validated acceptance deadline (unix seconds): `exp` plus the resolver's own skew. */
  acceptUntil: number;
  /**
   * Dot-paths under the leg's `extra` that were bound to authenticated
   * claims (plus the token field). `verifyX402EvcAuthorization` trims
   * `checkedLeg.extra` to exactly these, so nothing unverified reaches
   * settlement.
   */
  verifiedExtraPaths: string[];
}

export type PayeeResolver = (input: {
  audience: string;
  context: X402EvcContext;
  now: number;
}) => Promise<PayeeResolution>;

export interface IssuerQuoteKey {
  alg: JwsAlg;
  jwk: JWK;
}

export interface IssuerQuoteIssuer {
  /** Exact placeholder the challenge's `payTo` must carry. */
  payTo: string;
  scheme: string;
  network: string;
  /** REQUIRED token `aud` (the settlement rail, e.g. `aws:marketplace`). */
  audience: string;
  /** REQUIRED signed `payTo` claim (e.g. `seller`). */
  payToRole: string;
  keys: Map<string, IssuerQuoteKey>;
  /** `context.resource` → expected signed product claims (dot-path → primitive). */
  products: Map<string, Record<string, string | number | boolean>>;
  /** Challenge fields settlement consumes; each MUST equal the authenticated claim. */
  settlementFields: Array<{ challenge: string; claim: string }>;
  /**
   * Dot-paths under `extra` that MAY be present without being bound to a
   * claim (e.g. Tavily's `tier`). Any other unbound leaf under `extra` denies
   * `request_mismatch` (`extra_unbound`), and these never reach `checkedLeg`.
   */
  unboundExtraFields?: string[];
  /** Default 300; `maxLifetimeSeconds + 2 * clockSkewSeconds` MUST be at most 900. */
  maxLifetimeSeconds?: number;
}

export interface IssuerQuoteConfig {
  issuers: Map<string, IssuerQuoteIssuer>;
  /** Default `quoteToken`. */
  tokenField?: string;
  /** Default 60; 0..300. Applies to `exp`, `nbf`, `iat` only. */
  clockSkewSeconds?: number;
}

const MAX_IDENTIFIER = 256;
const MAX_JTI = 256;
const DEFAULT_SKEW = 60;
const MAX_SKEW = 300;
const DEFAULT_LIFETIME = 300;
const MAX_LIFETIME = 900;
const ISO4217_ASSET = /^iso4217:[A-Z]{3}$/;
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const CURVE_FOR_ALG: Record<JwsAlg, string> = { ES256: 'P-256', ES384: 'P-384' };

function configFault(reason: string, detail?: string): VerifyDenial {
  return new VerifyDenial('internal_error', 'issuer-quote configuration is invalid', {
    reason,
    ...(detail !== undefined ? { detail } : {}),
  });
}

function mismatch(reason: string, extra: Record<string, unknown> = {}): VerifyDenial {
  return new VerifyDenial('request_mismatch', 'x402 payee could not be bound to the quote issuer', {
    reason,
    ...extra,
  });
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_IDENTIFIER && !value.includes('\0');
}

function requireIdentifier(value: unknown, what: string): string {
  if (!isIdentifier(value)) throw configFault('identifier', what);
  return value;
}

/** Split and validate a dot-path: non-empty segments, none prototype-named. */
function parsePath(path: unknown, reason: string): string[] {
  if (typeof path !== 'string' || path.length === 0 || path.length > MAX_IDENTIFIER) throw configFault(reason, 'path');
  const segments = path.split('.');
  for (const segment of segments) {
    if (segment.length === 0 || FORBIDDEN_SEGMENTS.has(segment)) throw configFault(reason, `path:${path}`);
  }
  return segments;
}

/** Own-property walk over plain objects only. */
function lookup(root: unknown, segments: readonly string[]): { found: boolean; value?: unknown } {
  let current: unknown = root;
  for (const segment of segments) {
    if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, segment)) return { found: false };
    current = current[segment];
  }
  return { found: true, value: current };
}

/**
 * Configuration inputs may come from another realm or a library (jose's
 * exportJWK), so they are checked structurally, not by prototype identity.
 * Parsed token JSON keeps the strict same-realm check in jws.ts.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === '[object Object]';
}

function isPrimitive(value: unknown): value is string | number | boolean {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

interface CompiledKey {
  alg: JwsAlg;
  key: CryptoKey;
}

interface CompiledIssuer {
  payTo: string;
  scheme: string;
  network: string;
  audience: string;
  payToRole: string;
  keys: Map<string, CompiledKey>;
  products: Map<string, Array<{ segments: string[]; expected: string | number | boolean }>>;
  settlementFields: Array<{ challenge: string[]; claim: string[] }>;
  /** Leaf paths under `extra` that are allowed: token field, bound settlement paths, declared unbound fields. */
  allowedExtraPaths: Set<string>;
  verifiedExtraPaths: string[];
  maxLifetimeSeconds: number;
}

async function compileKey(kid: string, entry: unknown): Promise<CompiledKey> {
  if (!isRecord(entry)) throw configFault('keys', kid);
  const { alg, jwk } = entry;
  if (alg !== 'ES256' && alg !== 'ES384') throw configFault('jwk_alg', kid);
  if (!isRecord(jwk)) throw configFault('jwk_curve', kid);
  if (Object.prototype.hasOwnProperty.call(jwk, 'd')) throw configFault('jwk_private', kid);
  if (jwk.kty !== 'EC' || jwk.crv !== CURVE_FOR_ALG[alg] || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw configFault('jwk_curve', kid);
  }
  if ('alg' in jwk && jwk.alg !== alg) throw configFault('jwk_alg', kid);
  if ('use' in jwk && jwk.use !== 'sig') throw configFault('jwk_use', kid);
  if ('key_ops' in jwk && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) {
    throw configFault('jwk_key_ops', kid);
  }
  const publicJwk: JWK = { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  let key: CryptoKey;
  try {
    key = (await importJWK(publicJwk, alg)) as CryptoKey;
  } catch {
    throw configFault('jwk_curve', kid);
  }
  return { alg, key };
}

const MAX_ACCEPTANCE_WINDOW = 900;

/** Enumerate every leaf path under a value (arrays count as leaves). */
function leafPaths(value: unknown, prefix: string, out: string[]): void {
  if (isRecord(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0) { out.push(prefix); return; }
    for (const key of keys) leafPaths(value[key], prefix === '' ? key : `${prefix}.${key}`, out);
    return;
  }
  out.push(prefix);
}

async function compileIssuer(iss: string, raw: unknown, tokenField: string, skew: number): Promise<CompiledIssuer> {
  if (!isRecord(raw)) throw configFault('issuers', iss);
  const payTo = requireIdentifier(raw.payTo, 'payTo');
  const scheme = requireIdentifier(raw.scheme, 'scheme');
  const network = requireIdentifier(raw.network, 'network');
  const audience = requireIdentifier(raw.audience, 'audience');
  const payToRole = requireIdentifier(raw.payToRole, 'payToRole');

  if (!(raw.keys instanceof Map) || raw.keys.size === 0) throw configFault('keys', iss);
  const keys = new Map<string, CompiledKey>();
  for (const [kid, entry] of raw.keys) {
    keys.set(requireIdentifier(kid, 'kid'), await compileKey(kid, entry));
  }

  if (!(raw.products instanceof Map) || raw.products.size === 0) throw configFault('products', iss);
  const products = new Map<string, Array<{ segments: string[]; expected: string | number | boolean }>>();
  for (const [resource, record] of raw.products) {
    requireIdentifier(resource, 'resource');
    if (!isRecord(record) || Object.keys(record).length === 0) throw configFault('products', resource);
    const entries: Array<{ segments: string[]; expected: string | number | boolean }> = [];
    for (const [path, expected] of Object.entries(record)) {
      if (!isPrimitive(expected)) throw configFault('products', path);
      entries.push({ segments: parsePath(path, 'products'), expected });
    }
    products.set(resource, entries);
  }

  const fields = raw.settlementFields;
  if (!Array.isArray(fields) || fields.length === 0) throw configFault('settlement_fields', iss);
  const seen = new Set<string>();
  const settlementFields: Array<{ challenge: string[]; claim: string[] }> = [];
  for (const entry of fields) {
    if (!isRecord(entry)) throw configFault('settlement_fields', iss);
    const challenge = parsePath(entry.challenge, 'settlement_fields');
    const claim = parsePath(entry.claim, 'settlement_fields');
    const id = `${entry.challenge}\0${entry.claim}`;
    if (seen.has(id)) throw configFault('settlement_fields', 'duplicate');
    seen.add(id);
    settlementFields.push({ challenge, claim });
  }

  const maxLifetimeSeconds = raw.maxLifetimeSeconds ?? DEFAULT_LIFETIME;
  if (!Number.isInteger(maxLifetimeSeconds) || (maxLifetimeSeconds as number) < 1 || (maxLifetimeSeconds as number) > MAX_LIFETIME) {
    throw configFault('max_lifetime', iss);
  }
  // The resolver returns acceptUntil = exp + skew, `iat` may itself sit up to
  // `skew` ahead of the host clock, and a verifier bounds acceptUntil - now by
  // 900 by default: maxLifetime + 2*skew must fit, or a valid quote at the
  // edge of tolerance would be rejected downstream as internal_error (P2).
  if ((maxLifetimeSeconds as number) + 2 * skew > MAX_ACCEPTANCE_WINDOW) {
    throw configFault('max_lifetime', `${iss}: maxLifetimeSeconds + 2 * clockSkewSeconds exceeds ${MAX_ACCEPTANCE_WINDOW}`);
  }

  const verifiedExtraPaths = [tokenField];
  const allowedExtraPaths = new Set<string>([tokenField]);
  for (const { challenge } of settlementFields) {
    if (challenge[0] === 'extra' && challenge.length > 1) {
      const rel = challenge.slice(1).join('.');
      allowedExtraPaths.add(rel);
      verifiedExtraPaths.push(rel);
    }
  }
  const unbound = raw.unboundExtraFields ?? [];
  if (!Array.isArray(unbound)) throw configFault('unbound_extra_fields', iss);
  for (const path of unbound) allowedExtraPaths.add(parsePath(path, 'unbound_extra_fields').join('.'));

  return {
    payTo, scheme, network, audience, payToRole, keys, products, settlementFields,
    allowedExtraPaths, verifiedExtraPaths, maxLifetimeSeconds: maxLifetimeSeconds as number,
  };
}

/**
 * Build a {@link PayeeResolver} for issuer-signed quotes. Async because key
 * import is async; rejects with `internal_error` on any configuration fault
 * so a misconfigured host never silently fails open later.
 */
export async function createIssuerQuotePayeeResolver(config: IssuerQuoteConfig): Promise<PayeeResolver> {
  if (!isRecord(config)) throw configFault('config');
  if (!(config.issuers instanceof Map) || config.issuers.size === 0) throw configFault('issuers');
  const tokenField = config.tokenField ?? 'quoteToken';
  // A literal key under `extra`; a dot would be read as a nested path when
  // the checked leg is rebuilt, so it is rejected outright (P2).
  if (!isIdentifier(tokenField) || tokenField.includes('.')) throw configFault('token_field');
  const skew = config.clockSkewSeconds ?? DEFAULT_SKEW;
  if (!Number.isInteger(skew) || skew < 0 || skew > MAX_SKEW) throw configFault('clock_skew');

  const issuers = new Map<string, CompiledIssuer>();
  for (const [iss, raw] of config.issuers) {
    issuers.set(requireIdentifier(iss, 'iss'), await compileIssuer(iss, raw, tokenField, skew));
  }

  return async ({ audience, context, now }) => {
    if (!isUnixSeconds(now)) throw new VerifyDenial('internal_error', 'host clock did not produce a finite unix time');
    const issuer = issuers.get(audience);
    if (issuer === undefined) throw mismatch('issuer_unknown', { audience });
    const requirements: X402EvcRequirements = context.requirements;

    if (requirements.payTo !== issuer.payTo) throw mismatch('pay_to');
    if (requirements.scheme !== issuer.scheme) throw mismatch('scheme');
    if (requirements.network !== issuer.network) throw mismatch('network');
    const product = issuer.products.get(context.resource);
    if (product === undefined) throw mismatch('resource');
    if (typeof requirements.asset !== 'string' || !ISO4217_ASSET.test(requirements.asset)) throw mismatch('asset');

    const extra = requirements.extra;
    const token = isRecord(extra) ? extra[tokenField] : undefined;
    if (typeof token !== 'string') throw mismatch('token_missing');

    let compiledKey: CompiledKey;
    let verified: Awaited<ReturnType<typeof verifyCompactEs>>;
    try {
      const header = peekHeader(token);
      if (header.alg !== 'ES256' && header.alg !== 'ES384') throw new JwsRejected('alg');
      const kid = header.kid;
      const found = typeof kid === 'string' ? issuer.keys.get(kid) : undefined;
      if (found === undefined) throw mismatch('kid');
      compiledKey = found;
      verified = await verifyCompactEs(token, { key: compiledKey.key, alg: compiledKey.alg });
    } catch (err) {
      if (err instanceof JwsRejected) throw mismatch(err.reason === 'signature' ? 'signature' : `jws_${err.reason}`);
      throw err;
    }

    const claims = verified.payload;
    if (claims.iss !== audience) throw mismatch('iss');
    if (claims.aud !== issuer.audience) throw mismatch('aud');

    const { iat, exp, nbf, jti, price, payTo } = claims;
    if (!isUnixSeconds(iat) || !isUnixSeconds(exp) || jti === undefined || payTo === undefined || !isPlainObject(price)) {
      throw mismatch('claims');
    }
    if (nbf !== undefined && !isUnixSeconds(nbf)) throw mismatch('claims');
    if (!isIdentifier(jti) || jti.length > MAX_JTI) throw mismatch('jti');
    if (now > exp + skew) throw mismatch('exp');
    if (nbf !== undefined && nbf > now + skew) throw mismatch('nbf');
    if (iat > now + skew) throw mismatch('iat');
    if (iat >= exp || exp - iat > issuer.maxLifetimeSeconds) throw mismatch('lifetime');
    if (payTo !== issuer.payToRole) throw mismatch('pay_to_role');
    if (price.amount !== requirements.amount || price.currency !== requirements.asset.slice('iso4217:'.length)) {
      throw mismatch('price');
    }

    for (const { segments, expected } of product) {
      const got = lookup(claims, segments);
      if (!got.found || !isPrimitive(got.value) || typeof got.value !== typeof expected || got.value !== expected) {
        throw mismatch('product', { path: segments.join('.') });
      }
    }
    for (const { challenge, claim } of issuer.settlementFields) {
      const fromChallenge = lookup(requirements, challenge);
      const fromClaims = lookup(claims, claim);
      if (
        !fromChallenge.found || !fromClaims.found ||
        !isPrimitive(fromChallenge.value) || !isPrimitive(fromClaims.value) ||
        typeof fromChallenge.value !== typeof fromClaims.value || fromChallenge.value !== fromClaims.value
      ) {
        throw mismatch('settlement', { path: challenge.join('.') });
      }
    }

    // Every leaf under `extra` must be the token, a bound settlement field, or
    // a declared unbound field. Anything else is attacker-controllable bytes
    // that would otherwise ride into settlement.
    const leaves: string[] = [];
    leafPaths(extra, '', leaves);
    for (const leaf of leaves) {
      if (!issuer.allowedExtraPaths.has(leaf)) throw mismatch('extra_unbound', { path: `extra.${leaf}` });
    }

    const kid = verified.header.kid as string;
    return {
      binding: { kind: 'issuer_quote', issuer: audience, kid, jti, exp, token_sha256: verified.tokenSha256 },
      acceptUntil: exp + skew,
      verifiedExtraPaths: [...issuer.verifiedExtraPaths],
    };
  };
}
