/**
 * `bolyraGate(method, options)` — wrap an mppx server method so an agent's
 * delegated spend mandate is verified BEFORE the MPP payment flow proceeds.
 *
 * Integration shape: the adapter wraps `Method.Server` before it is passed to
 * `Mppx.create()` (the same convention as other mppx extensions), so no
 * middleware changes are needed and every mppx framework adapter — Express,
 * Hono, Elysia, Next.js — is covered automatically:
 *
 * ```ts
 * const mppx = Mppx.create({
 *   methods: [bolyraGate(tempoCharge, { audience, verifier })],
 *   secretKey,
 * })
 * ```
 *
 * Mechanics (HTTP transport):
 *   - The gate composes into the method's `preflight` hook, which mppx calls
 *     before the challenge/verification path. A denial returns an RFC 9457
 *     Problem Details response and fully handles the request — no challenge
 *     is issued, no credential is inspected, no payment logic runs.
 *   - On allow, the decision is stashed (keyed by mppx's captured-request
 *     snapshot) and the method's own `preflight` runs unchanged.
 *   - The gate also wraps `verify`: it FAILS CLOSED if payment verification
 *     is reached without a stashed allow (e.g. standalone
 *     `mppx.verifyCredential()` calls or non-HTTP transports, where the
 *     preflight hook never ran), and on success it attaches the
 *     authorization-receipt metadata to the mppx receipt (extension fields
 *     are preserved into the Payment-Receipt header by mppx).
 */

import { peekBundle } from './bundle';
import { parseBundle, type ParsedBundle } from './bundle';
import { verifyClassical } from './classical';
import { denyResponse } from './deny';
import { callUrlVerifier, runCommandVerifier } from './evc';
import { NonceStore } from './nonces';
import { buildDecisionReceiptInput, createGateReceiptSigner } from './receipts';
import { requiredTierForUsdAmount, tierCapability } from './tiers';
import {
  deny,
  isVerifyDenial,
  type BolyraGateOptions,
  type DenyVerdict,
  type FinancialTier,
  type GateDecision,
  type Verdict,
  type VerifierRequest,
} from './types';

/** Default request header carrying the presentation bundle. */
export const BOLYRA_AUTHORIZATION_HEADER = 'x-bolyra-authorization';

/**
 * Structural view of an mppx `Method.Server` — kept structural (no mppx
 * import) so `mppx` stays an optional peer dependency used only by consumers.
 */
export interface MppxServerMethodLike {
  name: string;
  intent: string;
  preflight?: (parameters: PreflightParameters) => unknown;
  verify: (parameters: VerifyParameters) => Promise<Record<string, unknown>>;
  [key: string]: unknown;
}

interface PreflightParameters {
  capturedRequest?: object | undefined;
  credential: unknown;
  input: Request;
  options: Record<string, unknown>;
  [key: string]: unknown;
}

interface VerifyParameters {
  envelope?: { capturedRequest: object } | undefined;
  [key: string]: unknown;
}

/** Extension field attached to the mppx receipt on an authorized payment. */
export interface BolyraAuthorizationReceiptField {
  decision: 'allow';
  tier: FinancialTier;
  capability: string;
  amountUsd: string;
  verifier: 'classical' | 'command' | 'url';
  audience: string;
  receipt?: GateDecision['receipt'];
}

function defaultAmountToUsd(context: { amount: unknown }): string | number {
  if (typeof context.amount === 'string' || typeof context.amount === 'number') {
    return context.amount;
  }
  throw new TypeError(
    'route options carry no usable `amount`; provide `amountToUsd` in the gate options',
  );
}

/**
 * Wrap an mppx server method with Bolyra spend-mandate authorization.
 * Fail-closed by design: every error path denies before payment logic runs.
 */
export function bolyraGate<method extends MppxServerMethodLike>(
  method: method,
  options: BolyraGateOptions,
): method {
  if (typeof options?.audience !== 'string' || options.audience.length === 0) {
    throw new TypeError('bolyraGate: `audience` is required');
  }
  const verifier = options.verifier;
  if (
    verifier === undefined ||
    (verifier.kind === 'classical' &&
      (!Array.isArray(verifier.trustedOperators) || verifier.trustedOperators.length === 0))
  ) {
    throw new TypeError(
      'bolyraGate: `verifier` is required — the default in-process mode needs ' +
        '`{ kind: "classical", trustedOperators: [...] }` (fail-closed: never "all operators trusted")',
    );
  }

  const program = options.program ?? 'mpp';
  const headerName = (options.header ?? BOLYRA_AUTHORIZATION_HEADER).toLowerCase();
  if (headerName === 'authorization') {
    throw new TypeError(
      'bolyraGate: `header` must not be "Authorization" — MPP\'s payment credential ' +
        'already rides that header; use a distinct header (default x-bolyra-authorization)',
    );
  }
  const enforce = options.enforce ?? 'always';
  const amountToUsd = options.amountToUsd ?? defaultAmountToUsd;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  // Fail fast on malformed key material, per the gateway receipt-signer.
  const receiptSigner = createGateReceiptSigner(options.receipts);
  // EVC §7.3 reserve-before-act storage. The default is in-memory and
  // per-gate-instance; deployments that need replay protection across
  // restarts or instances MUST inject a shared, durable store.
  const nonceStore = options.nonceStore ?? new NonceStore();

  /** Allow decisions stashed between preflight and verify, per request. */
  const decisions = new WeakMap<object, GateDecision>();

  async function dispatch(request: VerifierRequest): Promise<{
    verdict: Verdict;
    parsedBundle?: ParsedBundle;
  }> {
    switch (verifier.kind) {
      case 'classical': {
        const verdict = await verifyClassical(request, verifier.trustedOperators);
        if (verdict.verdict === 'allow') {
          // Safe re-parse for receipt metadata: verifyClassical already
          // accepted this exact bundle string.
          try {
            return { verdict, parsedBundle: parseBundle(request.bundle) };
          } catch {
            return { verdict };
          }
        }
        return { verdict };
      }
      case 'command':
        return { verdict: await runCommandVerifier(verifier, request) };
      case 'url':
        return { verdict: await callUrlVerifier(verifier, request) };
    }
  }

  async function decide(input: Request, routeOptions: Record<string, unknown>): Promise<
    | { outcome: 'allow'; decision: GateDecision }
    | { outcome: 'deny'; response: Response }
  > {
    let tier: FinancialTier | undefined;
    let amountUsd = '0';
    let requestContext: VerifierRequest['request'] = {
      agent_name: '',
      project_key: options.audience,
      program,
      model: options.model ?? '',
      granted_capabilities: [],
    };
    let parsedBundle: ParsedBundle | undefined;

    const denyWith = (verdict: Pick<DenyVerdict, 'code' | 'message'>): {
      outcome: 'deny';
      response: Response;
    } => {
      const signed = receiptSigner.sign(
        buildDecisionReceiptInput({
          request: requestContext,
          tier: tier ?? 'small',
          amountUsd,
          bundle: parsedBundle,
          denial: verdict,
        }),
      );
      options.onReceipt?.(signed);
      return { outcome: 'deny', response: denyResponse(verdict) };
    };

    try {
      // 1. The presentation header, before anything else.
      const bundleString = input.headers.get(headerName);
      if (bundleString === null || bundleString.trim().length === 0) {
        return denyWith(
          deny(
            'missing_authorization',
            `request carries no ${headerName} header with a Bolyra authorization presentation`,
          ),
        );
      }

      // 2. Resolve the route's amount to USD and map it to the delegated
      //    financial tier. Unresolvable amounts are a server-side
      //    misconfiguration and fail closed. NOTE: this is the amount the
      //    ROUTE was configured with, read at preflight time — BEFORE any
      //    method `request` hook runs. If a method's request hook can change
      //    the economic amount, the configured amount must remain
      //    authoritative for pricing (the mppx stable-binding fields pin
      //    amount across calls for standard methods), or `amountToUsd` must
      //    resolve the authoritative price itself. Documented in the README.
      try {
        const resolved = amountToUsd({ amount: routeOptions.amount, options: routeOptions });
        tier = requiredTierForUsdAmount(resolved);
        amountUsd = typeof resolved === 'number' ? String(resolved) : resolved.trim();
      } catch (err) {
        return denyWith(
          deny('internal_error', 'route amount could not be resolved for tier mapping'),
        );
      }
      const capability = tierCapability(tier);

      // 3. Echo the bundle's own identity fields into the verifier request
      //    (identifying, not restricting — see README). The load-bearing
      //    host-asserted fields are project_key (audience) and
      //    granted_capabilities (amount tier).
      const peek = peekBundle(bundleString);
      requestContext = {
        agent_name: peek.agent_name,
        project_key: options.audience,
        program,
        model: options.model ?? peek.model,
        granted_capabilities: [capability],
      };

      // 4. Delegate the decision to the configured verifier.
      const verifierRequest: VerifierRequest = {
        version: 1,
        bundle: bundleString,
        request: requestContext,
        now_unix: now(),
      };
      const outcome = await dispatch(verifierRequest);
      parsedBundle = outcome.parsedBundle;
      if (outcome.verdict.verdict === 'deny') {
        return denyWith(outcome.verdict);
      }

      // 5. Host nonce mode (spec §7.3): reserve-before-act every consumed
      //    nonce; a reservation conflict means the presentation was replayed.
      const consumeNonces = outcome.verdict.consume_nonces;
      if (consumeNonces !== undefined && consumeNonces.length > 0) {
        if (!(await nonceStore.reserve(consumeNonces, now()))) {
          return denyWith(deny('nonce_replayed', 'authorization presentation was already used'));
        }
      }

      // 6. Allow: sign the decision receipt and stash for the verify hook.
      const signed = receiptSigner.sign(
        buildDecisionReceiptInput({
          request: requestContext,
          tier,
          amountUsd,
          bundle: parsedBundle,
        }),
      );
      options.onReceipt?.(signed);

      return {
        outcome: 'allow',
        decision: {
          tier,
          capability,
          amountUsd,
          verifier: verifier.kind,
          request: requestContext,
          receipt: {
            payloadHash: signed.signature.payloadHash,
            signer: signed.signature.signer,
            issuer: receiptSigner.issuer,
            keyId: receiptSigner.keyId,
            seq: signed.payload.chain?.seq,
          },
        },
      };
    } catch (err) {
      // Nothing inside the gate may escape as an exception into the payment
      // flow: unknown faults deny (fail closed).
      if (isVerifyDenial(err)) return denyWith(err.toVerdict());
      return denyWith(deny('internal_error', 'authorization gate failed'));
    }
  }

  const originalPreflight = method.preflight?.bind(method);
  const originalVerify = method.verify.bind(method);

  const wrapped: MppxServerMethodLike = {
    ...method,

    async preflight(parameters: PreflightParameters): Promise<unknown> {
      const { capturedRequest, credential, input, options: routeOptions } = parameters;

      // `enforce: "payment"` skips the gate on credential-less requests so a
      // vanilla client can still discover the 402 challenge; the
      // credential-bearing retry is always gated.
      if (enforce === 'payment' && (credential === null || credential === undefined)) {
        return originalPreflight ? originalPreflight(parameters) : undefined;
      }

      const result = await decide(input, routeOptions ?? {});
      if (result.outcome === 'deny') {
        // Returning a Response from preflight fully handles the request —
        // the payment path never runs.
        return result.response;
      }

      if (capturedRequest !== undefined) {
        decisions.set(capturedRequest, result.decision);
      }
      return originalPreflight ? originalPreflight(parameters) : undefined;
    },

    async verify(parameters: VerifyParameters): Promise<Record<string, unknown>> {
      const key = parameters.envelope?.capturedRequest;
      const decision = key !== undefined ? decisions.get(key) : undefined;
      if (decision === undefined) {
        // Fail closed: payment verification was reached without a Bolyra
        // authorization decision for this request (standalone
        // verifyCredential(), non-HTTP transport, or a bypassed preflight).
        throw new Error(
          '@bolyra/mpp: payment verification reached without an authorization decision — ' +
            'denying (the gate covers HTTP request flows; see README for scope)',
        );
      }

      const receipt = await originalVerify(parameters);
      const bolyraAuthorization: BolyraAuthorizationReceiptField = {
        decision: 'allow',
        tier: decision.tier,
        capability: decision.capability,
        amountUsd: decision.amountUsd,
        verifier: decision.verifier,
        audience: decision.request.project_key,
        receipt: decision.receipt,
      };
      return { ...receipt, bolyraAuthorization };
    },
  };

  return wrapped as method;
}
