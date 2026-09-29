/**
 * x402 EVC authorization-evidence profile (spec/x402-evc-profile-v0.md).
 *
 * Bridges an x402 `PAYMENT-REQUIRED` flow into the External Verifier
 * Contract v1: the host builds one EVC §2.1 request carrying an `x402_evc`
 * extension member (envelope-level, §2.2 `additionalProperties` seam — the
 * `request` object and `bundle` are untouched, so every conformant v1
 * verifier keeps working), dispatches it to a configured verifier, and fails
 * closed to an RFC 9457 problem+json denial.
 *
 * This is ADDITIVE to the existing `x402.ts` adapter: that path carries a
 * mutual ZK handshake bound to a server challenge; this path carries an
 * operator-signed spend mandate (`bvp/1`) verified through the EVC — gate 1
 * (authorization evidence) of the two-gates model. Payee risk (gate 2) is out
 * of scope by design.
 *
 * Everything decision-shaped is reused from `@bolyra/mpp` (types, classical
 * verifier, EVC transports, denial vocabulary, nonce store) — this module
 * only owns the x402-shaped mapping and the host-side challenge checks.
 */

import type { PayeeBinding, PayeeResolver, PayeeResolution } from './x402-issuer-quote';
import type { X402Leg, X402LocalChallenge } from './x402-local-challenge';

import {
  BOLYRA_AUTHORIZATION_HEADER,
  DENY_STATUS,
  NonceStore,
  VerifyDenial,
  callUrlVerifier,
  deny,
  denyProblem,
  isVerifyDenial,
  peekBundle,
  requiredTierForUsdAmount,
  runCommandVerifier,
  tierCapability,
  verifyClassical,
  type ConsumeNonce,
  type DenyProblem,
  type NonceStoreLike,
  type Verdict,
  type VerifierConfig,
  type VerifierRequest,
} from '@bolyra/mpp';

// ---------------------------------------------------------------------------
// Profile constants
// ---------------------------------------------------------------------------

/** Profile identifier carried in every extension object. */
export const X402_EVC_PROFILE = 'x402_evc/0' as const;

/**
 * Request header carrying the `bvp/1` presentation — the same header
 * `@bolyra/mpp` uses, so one mandate travels identically across MPP and x402.
 */
export const X402_EVC_AUTHORIZATION_HEADER = BOLYRA_AUTHORIZATION_HEADER;

/** 402 response headers advertising the challenge context (spec §2 step 1). */
export const X402_EVC_NONCE_HEADER = 'x402-evc-nonce';
export const X402_EVC_EXPIRES_HEADER = 'x402-evc-expires';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The payment requirements the profile binds to — x402 v2 vocabulary
 * (`network` / `payTo` / atomic-unit string `amount`, per the x402
 * specification's `accepts` entries), NOT the legacy `x402.ts` adapter shape.
 */
export interface X402EvcRequirements {
  /** x402 v2 payment scheme (e.g. `exact`, `agent-pay`). Optional; pinned by §4.2 resolvers. */
  scheme?: string;
  /** x402 v2 network identifier (e.g. `base-sepolia`). */
  network: string;
  /** Asset identifier — token address or ISO currency code. */
  asset: string;
  /**
   * The x402 v2 `amount` string. For `iso4217:USD` this IS decimal USD
   * (e.g. `"0.016"`); for token assets it is integer atomic units.
   */
  amount: string;
  /** Payee address/identifier — x402 v2 `payTo`. */
  payTo: string;
  /**
   * Token decimals for the 1:1 USD-stablecoin atomic mapping. REQUIRED for
   * every non-`iso4217:*` asset (there is no default; omitting it fails
   * closed). This is the host's assertion that the asset is a 1:1 USD
   * stablecoin, not proof of that valuation. Ignored for `iso4217:*`.
   */
  assetDecimals?: number;
  /** x402 v2 `accepts[].extra`, carried for §4.2 resolvers (e.g. an issuer quote token). */
  extra?: Record<string, unknown>;
}

/** The 402 challenge context the resource server issued (spec §2 step 1). */
export interface X402EvcContext {
  /** Identifier of the paid resource being accessed (URL or route). */
  resource: string;
  /** The x402 payment requirements advertised in the 402. */
  requirements: X402EvcRequirements;
  /**
   * Single-use challenge nonce (opaque string). Known to BOTH sides before
   * the decision, so it doubles as the receipt instance discriminator:
   * profile decision receipts MUST carry it as
   * `instance.preimage.requestNonce` (spec/x402-evc-profile-v0.md §4.1,
   * spec/receipt-instance-binding-v1.md §3.2).
   */
  nonce: string;
  /** Unix seconds after which this challenge context is stale. */
  expiresAt: number;
}

/** The envelope-level extension member (spec §3). */
export interface X402EvcExtension {
  profile: typeof X402_EVC_PROFILE;
  resource: string;
  /** Decimal USD string. */
  amount: string;
  asset: string;
  network: string;
  payee: string;
  nonce: string;
  expires_at: number;
  verifier: VerifierConfig['kind'];
  /**
   * §4.2 issuer-quoted payee binding, when the host bound a placeholder
   * `payee` to a verified quote. A HOST ASSERTION for audit: it carries
   * neither the signature nor the signed claims, so it is not independently
   * verifiable from this member alone.
   */
  payee_binding?: PayeeBinding;
}

/** An EVC §2.1 request carrying the profile extension. */
export type X402EvcVerifierRequest = VerifierRequest & { x402_evc: X402EvcExtension };

/** Options shared by {@link buildX402EvcRequest} and {@link verifyX402EvcAuthorization}. */
export interface X402EvcOptions {
  /** The 402 challenge context. */
  context: X402EvcContext;
  /**
   * The audience/payee identity this host serves — compared byte-literally
   * against the mandate's signed `project_key` by the verifier; a mandate
   * signed for another payee denies `request_mismatch`.
   */
  audience: string;
  /** Verifier backend (EVC classical | command | url). */
  verifier: VerifierConfig;
  /** Binding `program` discriminator. Default `"x402"`. */
  program?: string;
  /** Optional model pin; when omitted, the binding's own model is echoed. */
  model?: string;
  /**
   * Resolve `requirements.amount` to a decimal USD string. Without it:
   * `iso4217:USD` amounts are decimal USD already, other `iso4217:*`
   * currencies fail closed, and token assets use the atomic mapping with an
   * explicit `assetDecimals`. The output MUST be a strict decimal string
   * (`^(0|[1-9]\d*)(\.\d{1,18})?$`); anything else fails closed.
   */
  amountToUsd?: (requirements: X402EvcRequirements) => string | number;
  /**
   * Decide whether the host's authorization audience covers the x402 payee.
   * Default: byte-literal equality `audience === requirements.payTo`. A
   * mismatch denies `request_mismatch` BEFORE any verifier runs — the default
   * v1 verifier does not evaluate the profile extension, so the host must own
   * this check (spec §3). Only literal `true` allows.
   */
  payeeMatches?: (audience: string, payTo: string) => boolean;
  /** Clock override (unix seconds). Tests only. */
  now?: () => number;
}

/**
 * Process-wide default nonce store — replay protection works out of the box
 * within one process. It does NOT survive restarts or span instances;
 * production deployments MUST inject a shared, durable `nonceStore`
 * (e.g. Redis `SET NX`), exactly as with `@bolyra/mpp`'s gate.
 */
const defaultNonceStore = new NonceStore();

/** Additional options for {@link verifyX402EvcAuthorization}. */
export interface X402EvcVerifyOptions extends Omit<X402EvcOptions, 'context'> {
  /** The 402 challenge context (server-participating mode). Exclusive with `localChallenge`. */
  context?: X402EvcContext;
  /**
   * Agent-side host mode (spec §4.2): a locally built challenge context.
   * Exclusive with `context`; REQUIRES `resolvePayee` (a local challenge has
   * no server nonce, so quote single-use is the replay protection).
   */
  localChallenge?: X402LocalChallenge;
  /**
   * Async payee binding (spec §4.2), e.g. `createIssuerQuotePayeeResolver`.
   * Exclusive with `payeeMatches`; both set is a configuration fault
   * (`internal_error`). Its `acceptUntil` caps the challenge deadline.
   */
  resolvePayee?: PayeeResolver;
  /** Upper bound on `acceptUntil - now` a resolver may return. Default 900. */
  maxAcceptanceSeconds?: number;
  /**
   * Reserve-before-act nonce store (EVC §7.3) for the challenge nonce AND any
   * verifier `consume_nonces`. Default: a process-wide in-memory store —
   * replay is refused within one process, but protection does not survive
   * restarts or span instances; inject a shared, durable store in production.
   */
  nonceStore?: NonceStoreLike;
}

/** The profile's decision result. */
export interface X402EvcDecision {
  allowed: boolean;
  /** 200 on allow; `DENY_STATUS[code]` on deny. */
  status: number;
  /** The verdict (verifier-produced, or host-local for gate-side denials). */
  verdict: Verdict;
  /** RFC 9457 problem body — present exactly when denied. */
  problem?: DenyProblem;
  /** The request that was (or would have been) dispatched, for audit. */
  request?: X402EvcVerifierRequest;
  /** The finalized challenge deadline used for the request and the reservation (allow only). */
  expiresAt?: number;
  /**
   * Local mode, allow only: the deep-frozen leg that was verified. This is
   * the ONLY object a host may pass to settlement; every denial omits it.
   */
  checkedLeg?: Readonly<X402Leg>;
}

/** A usable unix-seconds timestamp: finite, non-negative, below 2^40 (A3). */
export function isUnixSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 2 ** 40;
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

const ISO4217_ASSET = /^iso4217:[A-Z]{3}$/;
const DECIMAL_AMOUNT = /^(0|[1-9]\d*)(\.\d{1,18})?$/;
const INTEGER_AMOUNT = /^(0|[1-9]\d*)$/;
const MAX_AMOUNT_CHARS = 40;
const MAX_USD = 1e15;

function unusableAmount(requirements: X402EvcRequirements, reason: string): VerifyDenial {
  return new VerifyDenial('internal_error', 'amount did not resolve to a usable USD value', {
    amount: requirements.amount,
    asset: requirements.asset,
    reason,
  });
}

/** Atomic integer units → exact decimal string via BigInt (no float round-trip). */
function atomicToDecimal(amount: string, decimals: number): string {
  const scale = 10n ** BigInt(decimals);
  const value = BigInt(amount);
  const whole = value / scale;
  const frac = (value % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return frac.length > 0 ? `${whole}.${frac}` : `${whole}`;
}

/**
 * Resolve the challenge amount to a decimal USD string. Asset policy is
 * explicit and fail-closed (A2, 2026-09-29):
 *   - `iso4217:USD` — the amount IS decimal USD (Tavily agent-pay shape).
 *   - other `iso4217:*` — no implicit conversion; `amountToUsd` is required.
 *   - anything else — the legacy 1:1 USD-stablecoin atomic mapping, ONLY when
 *     the host asserts `assetDecimals` explicitly. That assertion is the
 *     host's, not proof of the valuation.
 * A custom `amountToUsd` bypasses the asset policy but not the result checks.
 */
function resolveUsdAmount(
  requirements: X402EvcRequirements,
  amountToUsd?: (requirements: X402EvcRequirements) => string | number,
): string {
  const { amount, asset } = requirements;
  if (typeof amount !== 'string' || amount.length === 0 || amount.length > MAX_AMOUNT_CHARS) {
    throw unusableAmount(requirements, 'amount_syntax');
  }

  let usd: string;
  if (amountToUsd !== undefined) {
    const raw = amountToUsd(requirements);
    usd = typeof raw === 'number' ? String(raw) : raw;
    if (typeof usd !== 'string' || usd.length > MAX_AMOUNT_CHARS || !DECIMAL_AMOUNT.test(usd)) {
      throw unusableAmount(requirements, 'converter_output');
    }
  } else if (typeof asset === 'string' && asset.startsWith('iso4217:')) {
    if (!ISO4217_ASSET.test(asset)) throw unusableAmount(requirements, 'iso4217_syntax');
    if (asset !== 'iso4217:USD') throw unusableAmount(requirements, 'iso4217_currency_unsupported');
    if (!DECIMAL_AMOUNT.test(amount)) throw unusableAmount(requirements, 'amount_syntax');
    usd = amount;
  } else {
    const decimals = requirements.assetDecimals;
    if (decimals === undefined) throw unusableAmount(requirements, 'asset_decimals_required');
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
      throw unusableAmount(requirements, 'asset_decimals_range');
    }
    if (!INTEGER_AMOUNT.test(amount)) throw unusableAmount(requirements, 'amount_syntax');
    usd = atomicToDecimal(amount, decimals);
  }

  const asNumber = Number(usd);
  if (!Number.isFinite(asNumber) || asNumber <= 0 || asNumber > MAX_USD) {
    throw unusableAmount(requirements, 'amount_range');
  }
  return usd;
}

/**
 * Build the EVC §2.1 request + `x402_evc` extension for one x402 retry
 * (spec §3). Throws {@link VerifyDenial} on unusable inputs — callers either
 * let {@link verifyX402EvcAuthorization} convert that to a denial or handle
 * it themselves. Fail closed; never guess.
 */
export function buildX402EvcRequest(
  options: X402EvcOptions & { bundle: string },
): X402EvcVerifierRequest {
  return buildX402EvcRequestInternal(options, undefined);
}

/**
 * Private: build with an already-verified §4.2 payee binding. When `binding`
 * is present the byte-equality payee check is skipped because the host
 * bound the payee through `resolvePayee`; the binding is recorded on the
 * extension. Not exported: no public data-shaped bypass.
 */
function buildX402EvcRequestInternal(
  options: X402EvcOptions & { bundle: string },
  binding: PayeeBinding | undefined,
): X402EvcVerifierRequest {
  const { bundle, context, audience, verifier } = options;
  const nowUnix = options.now !== undefined ? options.now() : Math.floor(Date.now() / 1000);

  // The host owns the payee check (spec §3): the default v1 verifier does not
  // evaluate the profile extension, so an audience/payTo mismatch must fail
  // closed here, before any verifier can allow.
  const payeeMatches = options.payeeMatches ?? ((a: string, p: string) => a === p);
  const matched: unknown = binding !== undefined ? true : payeeMatches(audience, context.requirements.payTo);
  if (matched !== true) {
    // Only literal `true` allows. A Promise (or any thenable) is truthy and
    // would otherwise fail open; assimilate it so a rejection cannot surface
    // as an unhandled rejection, then deny without waiting for it.
    if (isThenable(matched)) Promise.resolve(matched).catch(() => undefined);
    throw new VerifyDenial('request_mismatch', 'x402 payee does not match the authorization audience', {
      audience,
      pay_to: context.requirements.payTo,
    });
  }

  const usd = resolveUsdAmount(context.requirements, options.amountToUsd);
  const tier = requiredTierForUsdAmount(usd);
  const capability = tierCapability(tier);

  const peek = peekBundle(bundle); // throws VerifyDenial on malformed bundles

  return {
    version: 1,
    bundle,
    request: {
      agent_name: peek.agent_name,
      project_key: audience,
      program: options.program ?? 'x402',
      model: options.model ?? peek.model,
      granted_capabilities: [capability],
    },
    now_unix: nowUnix,
    x402_evc: {
      profile: X402_EVC_PROFILE,
      resource: context.resource,
      amount: usd,
      asset: context.requirements.asset,
      network: context.requirements.network,
      payee: context.requirements.payTo,
      nonce: context.nonce,
      expires_at: context.expiresAt,
      verifier: verifier.kind,
      ...(binding !== undefined ? { payee_binding: binding } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

function dispatchVerifier(
  config: VerifierConfig,
  request: X402EvcVerifierRequest,
): Promise<Verdict> {
  switch (config.kind) {
    case 'classical':
      return verifyClassical(request, config.trustedOperators);
    case 'command':
      return runCommandVerifier(config, request);
    case 'url':
      return callUrlVerifier(config, request);
  }
}

function denied(verdict: Verdict & { verdict: 'deny' }, request?: X402EvcVerifierRequest): X402EvcDecision {
  const problem = denyProblem(verdict);
  return { allowed: false, status: problem.status, verdict, problem, request };
}

const DEFAULT_MAX_ACCEPTANCE_SECONDS = 900;
const MAX_LOCAL_DEADLINE_SECONDS = 900;
const MAX_BINDING_STRING = 256;

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const key of Object.keys(value as object)) deepFreeze((value as Record<string, unknown>)[key]);
    Object.freeze(value);
  }
  return value;
}

/** Deep, frozen copy of the challenge context so later caller mutation cannot reach the verified data. */
function snapshotContext(context: X402EvcContext): X402EvcContext {
  return deepFreeze(structuredClone(context));
}

function isBoundedString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_BINDING_STRING && !value.includes('\0');
}

function deepEqualJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object).sort();
  const kb = Object.keys(b as object).sort();
  if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false;
  return ka.every((k) => deepEqualJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/** Local-mode invariants (spec §4.2) checked against the SNAPSHOT; returns a fault message or undefined. */
function validateLocalChallenge(local: X402LocalChallenge, context: X402EvcContext): string | undefined {
  if (local.mode !== 'local') return 'localChallenge.mode must be "local"';
  if (typeof local.headerSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(local.headerSha256)) return 'localChallenge.headerSha256 is malformed';
  if (context.nonce !== local.headerSha256) return 'localChallenge nonce is not the header hash';
  if (!isUnixSeconds(local.receivedAt)) return 'localChallenge.receivedAt is not a finite unix time';
  if (context.expiresAt > local.receivedAt + MAX_LOCAL_DEADLINE_SECONDS) return 'localChallenge deadline exceeds the local cap';
  const leg = local.selectedLeg;
  if (typeof leg !== 'object' || leg === null) return 'localChallenge.selectedLeg is missing';
  const r = context.requirements;
  for (const field of ['scheme', 'network', 'asset', 'amount', 'payTo'] as const) {
    if (leg[field] !== r[field]) return `localChallenge.selectedLeg.${field} disagrees with the verified requirements`;
  }
  if (!deepEqualJson(leg.extra ?? undefined, r.extra ?? undefined)) return 'localChallenge.selectedLeg.extra disagrees with the verified requirements';
  if (!Number.isInteger(leg.maxTimeoutSeconds) || leg.maxTimeoutSeconds <= 0) return 'localChallenge.selectedLeg.maxTimeoutSeconds is not usable';
  return undefined;
}

/** The checked leg: the verified snapshot, with `extra` trimmed to the verified paths (H1). */
function buildCheckedLeg(leg: X402Leg, verifiedExtraPaths: readonly string[]): Readonly<X402Leg> {
  const out: X402Leg = {
    scheme: leg.scheme, network: leg.network, asset: leg.asset, amount: leg.amount, payTo: leg.payTo,
    maxTimeoutSeconds: leg.maxTimeoutSeconds,
  };
  if (leg.extra !== undefined) {
    const trimmed: Record<string, unknown> = {};
    for (const path of verifiedExtraPaths) {
      const segments = path.split('.');
      let src: unknown = leg.extra;
      let found = true;
      for (const seg of segments) {
        if (typeof src !== 'object' || src === null || !Object.prototype.hasOwnProperty.call(src, seg)) { found = false; break; }
        src = (src as Record<string, unknown>)[seg];
      }
      if (!found) continue;
      let dst = trimmed;
      for (const seg of segments.slice(0, -1)) {
        if (typeof dst[seg] !== 'object' || dst[seg] === null) dst[seg] = {};
        dst = dst[seg] as Record<string, unknown>;
      }
      dst[segments[segments.length - 1]] = structuredClone(src);
    }
    out.extra = trimmed;
  }
  return deepFreeze(out);
}

/** Validate a resolver's output; returns the fault message, or undefined when usable. */
function validateResolution(
  resolution: unknown,
  audience: string,
  nowUnix: number,
  maxAcceptance: number,
): string | undefined {
  if (typeof resolution !== 'object' || resolution === null) return 'payee resolver returned no result';
  const { binding, acceptUntil } = resolution as { binding?: unknown; acceptUntil?: unknown };
  if (typeof binding !== 'object' || binding === null) return 'payee resolver returned no binding';
  const b = binding as Record<string, unknown>;
  if (b.kind !== 'issuer_quote') return 'payee binding kind is not supported';
  if (!isBoundedString(b.issuer) || !isBoundedString(b.kid) || !isBoundedString(b.jti)) return 'payee binding identifiers are not usable';
  if (b.issuer !== audience) return 'payee binding issuer does not equal the host audience';
  if (!isUnixSeconds(b.exp)) return 'payee binding exp is not a finite unix time';
  if (typeof b.token_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(b.token_sha256)) return 'payee binding token hash is malformed';
  if (!isUnixSeconds(acceptUntil)) return 'payee resolver acceptUntil is not a finite unix time';
  if (acceptUntil < b.exp) return 'payee resolver acceptUntil precedes the binding exp';
  if (acceptUntil - nowUnix > maxAcceptance) return 'payee resolver acceptUntil exceeds maxAcceptanceSeconds';
  const paths = (resolution as { verifiedExtraPaths?: unknown }).verifiedExtraPaths;
  if (!Array.isArray(paths) || paths.length > 256 || paths.some((p) => !isBoundedString(p))) return 'payee resolver verifiedExtraPaths is malformed';
  return undefined;
}

/**
 * Verify one x402 retry's authorization evidence (spec §2 step 3).
 *
 * Order of checks — host obligations first, then the verifier's decision:
 *   1. header present (else `missing_authorization`, 401)
 *   2. challenge context fresh (else `expired`, 403 — host-owned)
 *   3. build request (malformed bundle / unusable amount fail closed)
 *   4. dispatch to the configured verifier (every transport failure is a deny)
 *   5. reserve the challenge nonce + any verifier `consume_nonces`
 *      atomically, reserve-before-act (else `nonce_replayed`, 403)
 */
export async function verifyX402EvcAuthorization(
  presentation: string | null | undefined,
  options: X402EvcVerifyOptions,
): Promise<X402EvcDecision> {
  try {
    return await verifyInner(presentation, options);
  } catch {
    // The contract is "always a decision, never a throw" (§4).
    return denied(deny('internal_error', 'verification failed unexpectedly'));
  }
}

async function verifyInner(
  presentation: string | null | undefined,
  options: X402EvcVerifyOptions,
): Promise<X402EvcDecision> {
  // Snapshot every security-relevant option synchronously, before any await
  // (M1): a caller sharing one options object across concurrent calls must
  // not be able to change the audience, verifier, clock or store mid-flight.
  const {
    audience, verifier, amountToUsd, program, model, payeeMatches, resolvePayee,
    localChallenge: local, nonceStore, maxAcceptanceSeconds,
  } = options;
  const clock = options.now;
  const readClock = (): number => (clock !== undefined ? clock() : Math.floor(Date.now() / 1000));
  const nowUnix = readClock();
  if (!isUnixSeconds(nowUnix)) {
    return denied(deny('internal_error', 'host clock did not produce a finite unix time'));
  }
  if (typeof audience !== 'string' || audience.length === 0) {
    return denied(deny('internal_error', 'audience is required'));
  }

  // Mode selection (spec §4.2): exactly one of context / localChallenge.
  if ((options.context === undefined) === (local === undefined)) {
    return denied(deny('internal_error', 'exactly one of context or localChallenge is required'));
  }
  if (local !== undefined && resolvePayee === undefined) {
    return denied(deny('internal_error', 'local mode requires resolvePayee (quote single-use is the replay protection)'));
  }
  if (resolvePayee !== undefined && payeeMatches !== undefined) {
    return denied(deny('internal_error', 'resolvePayee and payeeMatches are mutually exclusive'));
  }
  const maxAcceptance = maxAcceptanceSeconds ?? DEFAULT_MAX_ACCEPTANCE_SECONDS;
  if (!Number.isInteger(maxAcceptance) || maxAcceptance < 1 || maxAcceptance > 2 ** 40) {
    return denied(deny('internal_error', 'maxAcceptanceSeconds is not a usable bound'));
  }

  // Snapshot the challenge (deep clone + freeze), then validate THE SNAPSHOT
  // (L3): a getter that changes between reads cannot smuggle a bad value past
  // the guard.
  const rawContext = options.context ?? local?.context;
  if (typeof rawContext !== 'object' || rawContext === null) {
    return denied(deny('internal_error', 'challenge context is required'));
  }
  let context: X402EvcContext;
  try {
    context = snapshotContext(rawContext);
  } catch {
    return denied(deny('internal_error', 'challenge context is not snapshot-able'));
  }
  if (!isUnixSeconds(context.expiresAt)) {
    return denied(deny('internal_error', 'challenge expiresAt is not a finite unix time'));
  }
  if (typeof context.nonce !== 'string' || context.nonce.length === 0 || context.nonce.length > 256 || context.nonce.includes('\0')) {
    return denied(deny('internal_error', 'challenge nonce is not a usable identifier'));
  }
  if (typeof context.resource !== 'string' || typeof context.requirements !== 'object' || context.requirements === null) {
    return denied(deny('internal_error', 'challenge context is malformed'));
  }

  // Local mode (L2/G2): the selected leg must be exactly what the snapshot
  // verifies, and the local invariants must hold, or the "checked leg"
  // guarantee would be a lie.
  let localLeg: X402Leg | undefined;
  if (local !== undefined) {
    const fault = validateLocalChallenge(local, context);
    if (fault !== undefined) return denied(deny('internal_error', fault));
    localLeg = structuredClone(local.selectedLeg);
  }

  if (typeof presentation !== 'string' || presentation.trim() === '') {
    return denied(deny('missing_authorization', 'no authorization presentation on the request'));
  }

  if (context.expiresAt <= nowUnix) {
    return denied(deny('expired', 'the x402 challenge context has expired'));
  }

  // §4.2: bind the payee through the resolver BEFORE building the request.
  let resolution: PayeeResolution | undefined;
  let expiresAt = context.expiresAt;
  if (resolvePayee !== undefined) {
    try {
      resolution = await resolvePayee({ audience, context, now: nowUnix });
    } catch (err) {
      if (isVerifyDenial(err)) return denied(err.toVerdict());
      return denied(deny('internal_error', 'payee resolver failed'));
    }
    const fault = validateResolution(resolution, audience, nowUnix, maxAcceptance);
    if (fault !== undefined) return denied(deny('internal_error', fault));
    // Fresh time after the await: both the challenge and the quote must still be live.
    const afterResolve = readClock();
    if (!isUnixSeconds(afterResolve)) return denied(deny('internal_error', 'host clock did not produce a finite unix time'));
    if (context.expiresAt <= afterResolve) return denied(deny('expired', 'the x402 challenge context has expired'));
    if (resolution.acceptUntil <= afterResolve) return denied(deny('expired', 'the quote acceptance deadline has passed'));
    expiresAt = Math.min(context.expiresAt, resolution.acceptUntil);
    context = Object.freeze({ ...context, expiresAt });
  }

  let request: X402EvcVerifierRequest;
  try {
    request = buildX402EvcRequestInternal(
      { context, audience, verifier, amountToUsd, program, model, payeeMatches, bundle: presentation, now: () => nowUnix },
      resolution?.binding,
    );
  } catch (err) {
    if (isVerifyDenial(err)) return denied(err.toVerdict());
    return denied(deny('internal_error', 'failed to build the verifier request'));
  }

  let verdict: Verdict;
  try {
    verdict = await dispatchVerifier(verifier, request);
  } catch {
    // The transports already fail closed internally; this guards the
    // in-process classical path and any unexpected throw. Never an allow.
    return denied(deny('internal_error', 'verifier dispatch failed'), request);
  }
  if (verdict.verdict === 'deny') {
    return denied(verdict, request);
  }

  // Fresh time after dispatch: re-check the finalized deadline (challenge and quote).
  const afterDispatch = readClock();
  if (!isUnixSeconds(afterDispatch)) return denied(deny('internal_error', 'host clock did not produce a finite unix time'), request);
  if (expiresAt <= afterDispatch) return denied(deny('expired', 'the x402 challenge context has expired'), request);

  // Reserve-before-act (§7.3): the challenge nonce, the quote's (issuer, jti)
  // through its whole acceptance window, and any nonces the verifier asked
  // the host to burn — atomically, deduplicated on the exact (issuer_key,
  // nonce) PAIR (never a joined string, I1) keeping the longest retention, so
  // a replayed challenge, quote or presentation is refused before payment.
  const store = nonceStore ?? defaultNonceStore;
  const raw: ConsumeNonce[] = [
    { issuer_key: `x402_evc:${audience}`, nonce: context.nonce, retain_until: expiresAt },
    ...(resolution !== undefined
      ? [{ issuer_key: `x402_evc_quote:${resolution.binding.issuer}`, nonce: resolution.binding.jti, retain_until: resolution.acceptUntil }]
      : []),
    ...(verdict.consume_nonces ?? []),
  ];
  const byIssuer = new Map<string, Map<string, ConsumeNonce>>();
  for (const entry of raw) {
    if (typeof entry.issuer_key !== 'string' || typeof entry.nonce !== 'string' || !isUnixSeconds(entry.retain_until)) {
      return denied(deny('internal_error', 'nonce entry is malformed'), request);
    }
    if (entry.issuer_key.includes('\0') || entry.nonce.includes('\0')) {
      return denied(deny('internal_error', 'nonce identifiers must not contain NUL'), request);
    }
    let perIssuer = byIssuer.get(entry.issuer_key);
    if (perIssuer === undefined) { perIssuer = new Map(); byIssuer.set(entry.issuer_key, perIssuer); }
    const prior = perIssuer.get(entry.nonce);
    if (prior === undefined || entry.retain_until > prior.retain_until) perIssuer.set(entry.nonce, { ...entry });
  }
  const entries: ConsumeNonce[] = [];
  for (const perIssuer of byIssuer.values()) entries.push(...perIssuer.values());
  let reserved: unknown;
  try {
    reserved = await store.reserve(entries, afterDispatch);
  } catch {
    // A broken nonce store cannot prove non-replay — fail closed (§7.3),
    // never an allow, and never an unhandled rejection.
    return denied(deny('internal_error', 'nonce reservation failed'), request);
  }
  if (reserved === false) {
    return denied(deny('nonce_replayed', 'challenge nonce or presentation nonce already used'), request);
  }
  if (reserved !== true) {
    // Only literal true proves the reservation (L1); a truthy object is not proof.
    return denied(deny('internal_error', 'nonce store returned a non-boolean result'), request);
  }
  // Final re-check after reservation: the reservation is already burned,
  // which is the correct side of the race — never an allow past the deadline.
  const afterReserve = readClock();
  if (!isUnixSeconds(afterReserve)) return denied(deny('internal_error', 'host clock did not produce a finite unix time'), request);
  if (expiresAt <= afterReserve) return denied(deny('expired', 'the x402 challenge context expired during reservation'), request);

  const checkedLeg = localLeg !== undefined && resolution !== undefined
    ? buildCheckedLeg(localLeg, resolution.verifiedExtraPaths)
    : undefined;

  return {
    allowed: true,
    status: 200,
    verdict,
    request,
    expiresAt,
    ...(checkedLeg !== undefined ? { checkedLeg } : {}),
  };
}
