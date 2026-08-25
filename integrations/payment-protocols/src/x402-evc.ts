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
  /** x402 v2 network identifier (e.g. `base-sepolia`). */
  network: string;
  /** Asset identifier — token address or ISO currency code. */
  asset: string;
  /** Amount in atomic token units, as a decimal string (x402 v2 shape). */
  amount: string;
  /** Payee address/identifier — x402 v2 `payTo`. */
  payTo: string;
  /**
   * Token decimals used by the default USD mapping (assumes a 1:1 USD
   * stablecoin). Default 6 (USDC). Non-USD assets MUST supply `amountToUsd`.
   */
  assetDecimals?: number;
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
   * Resolve `requirements.amount` (atomic units) to a decimal USD value.
   * Default assumes a 1:1 USD stablecoin with `assetDecimals` (default 6,
   * USDC). Non-USD assets MUST provide this. Unresolvable amounts fail closed
   * (`internal_error`).
   */
  amountToUsd?: (requirements: X402EvcRequirements) => string | number;
  /**
   * Decide whether the host's authorization audience covers the x402 payee.
   * Default: byte-literal equality `audience === requirements.payTo`. A
   * mismatch denies `request_mismatch` BEFORE any verifier runs — conformant
   * EVC verifiers ignore the profile extension, so the host must own this
   * check (spec §4).
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
export interface X402EvcVerifyOptions extends X402EvcOptions {
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
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

function resolveUsdAmount(
  requirements: X402EvcRequirements,
  amountToUsd?: (requirements: X402EvcRequirements) => string | number,
): string {
  let raw: string | number;
  if (amountToUsd !== undefined) {
    raw = amountToUsd(requirements);
  } else {
    // Default: 1:1 USD stablecoin in atomic units (assetDecimals, default 6).
    const atomic = Number(requirements.amount);
    const decimals = requirements.assetDecimals ?? 6;
    if (
      requirements.amount.trim() === '' ||
      !Number.isFinite(atomic) ||
      !Number.isInteger(decimals) ||
      decimals < 0
    ) {
      throw new VerifyDenial('internal_error', 'amount did not resolve to a usable USD value', {
        amount: requirements.amount,
      });
    }
    raw = atomic / 10 ** decimals;
  }
  const asNumber = typeof raw === 'number' ? raw : Number(raw);
  if (typeof raw === 'string' && raw.trim() === '') {
    throw new VerifyDenial('internal_error', 'amount resolved to an empty string');
  }
  if (!Number.isFinite(asNumber) || asNumber < 0) {
    throw new VerifyDenial('internal_error', 'amount did not resolve to a usable USD value', {
      amount: requirements.amount,
    });
  }
  return typeof raw === 'string' ? raw : String(raw);
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
  const { bundle, context, audience, verifier } = options;
  const nowUnix = options.now !== undefined ? options.now() : Math.floor(Date.now() / 1000);

  // The host owns the payee check (spec §4): conformant EVC verifiers ignore
  // the profile extension, so an audience/payTo mismatch must fail closed
  // here, before any verifier can allow.
  const payeeMatches = options.payeeMatches ?? ((a: string, p: string) => a === p);
  if (!payeeMatches(audience, context.requirements.payTo)) {
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
  const nowUnix = options.now !== undefined ? options.now() : Math.floor(Date.now() / 1000);

  if (presentation === null || presentation === undefined || presentation.trim() === '') {
    return denied(deny('missing_authorization', 'no authorization presentation on the request'));
  }

  if (options.context.expiresAt <= nowUnix) {
    return denied(deny('expired', 'the x402 challenge context has expired'));
  }

  let request: X402EvcVerifierRequest;
  try {
    request = buildX402EvcRequest({ ...options, bundle: presentation });
  } catch (err) {
    if (isVerifyDenial(err)) return denied(err.toVerdict());
    return denied(deny('internal_error', 'failed to build the verifier request'));
  }

  let verdict: Verdict;
  try {
    verdict = await dispatchVerifier(options.verifier, request);
  } catch {
    // The transports already fail closed internally; this guards the
    // in-process classical path and any unexpected throw. Never an allow.
    return denied(deny('internal_error', 'verifier dispatch failed'), request);
  }
  if (verdict.verdict === 'deny') {
    return denied(verdict, request);
  }

  // Reserve-before-act (§7.3): the profile's challenge nonce plus any nonces
  // the verifier asked the host to burn — atomically, so a replayed challenge
  // and a replayed presentation are both refused before any payment logic.
  const store = options.nonceStore ?? defaultNonceStore;
  const entries: ConsumeNonce[] = [
    {
      issuer_key: `x402_evc:${options.audience}`,
      nonce: options.context.nonce,
      retain_until: options.context.expiresAt,
    },
    ...(verdict.consume_nonces ?? []),
  ];
  let reserved: boolean;
  try {
    reserved = await store.reserve(entries, nowUnix);
  } catch {
    // A broken nonce store cannot prove non-replay — fail closed (§7.3),
    // never an allow, and never an unhandled rejection.
    return denied(deny('internal_error', 'nonce reservation failed'), request);
  }
  if (!reserved) {
    return denied(deny('nonce_replayed', 'challenge nonce or presentation nonce already used'), request);
  }

  return { allowed: true, status: 200, verdict, request };
}
