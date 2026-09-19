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
 *     before the challenge/verification path. A denial THROWS a
 *     `BolyraDeniedError` carrying the verdict and its RFC 9457 Problem
 *     Details response (see `handleDenials`) — no challenge is issued, no
 *     credential is inspected, no payment logic runs, and the route handler's
 *     own statements after `mppx.charge(...)(request)` never execute. (A
 *     returned non-402 Response would be turned into outer status 200 by
 *     mppx, and the application would run its protected action.)
 *   - On allow, the decision is stashed (keyed by mppx's captured-request
 *     snapshot) and the method's own `preflight` runs unchanged.
 *   - The gate also wraps `verify`: it FAILS CLOSED if payment verification
 *     is reached without a stashed allow (e.g. standalone
 *     `mppx.verifyCredential()` calls or non-HTTP transports, where the
 *     preflight hook never ran), and on success it attaches the
 *     authorization-receipt metadata to the mppx receipt (extension fields
 *     are preserved into the Payment-Receipt header by mppx).
 */

import type { SignedReceipt } from '@bolyra/receipts';
import { peekBundle } from './bundle';
import { parseBundle, type ParsedBundle } from './bundle';
import { verifyClassical } from './classical';
import { denyResponse } from './deny';
import { BolyraDeniedError } from './errors';
import { callUrlVerifier, runCommandVerifier } from './evc';
import { NonceStore } from './nonces';
import {
  buildDecisionInstance,
  buildDecisionReceiptInput,
  createGateReceiptSigner,
  instanceFactsFrom,
  type DecisionReceiptFacts,
} from './receipts';
import { requiredTierForUsdAmount, tierCapability } from './tiers';
import {
  AUDIENCE_IDENTIFIER_PATTERN,
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
  // Method syntax (bivariant parameters), not property syntax: under
  // `strictFunctionTypes` a property-typed hook would check a real mppx
  // `Method.Server`'s narrower parameter types contravariantly and fail the
  // `bolyraGate<method>` constraint, degrading the return type.
  preflight?(parameters: PreflightParameters): unknown;
  verify(parameters: VerifyParameters): Promise<Record<string, unknown>>;
  [key: string]: unknown;
}

interface PreflightParameters {
  capturedRequest?: object | undefined;
  credential: unknown;
  input: Request;
  options: Record<string, unknown>;
  realm?: string;
  secretKey?: string;
  [key: string]: unknown;
}

interface VerifyParameters {
  envelope?: { capturedRequest: object } | undefined;
  credential?: unknown;
  request?: Record<string, unknown>;
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
  if (!AUDIENCE_IDENTIFIER_PATTERN.test(options.audience)) {
    throw new TypeError(
      'bolyraGate: `audience` must be a stable machine identifier (printable ASCII ' +
        'excluding space, 1..256 chars — spec/receipt-instance-binding-v1.md §3.1.1); ' +
        'display names belong outside the signed surface',
    );
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
  // Non-empty ASCII, agreeing with issueMandate: an empty program would put
  // a signed, verifier-valid instance ref over an empty discriminator.
  // eslint-disable-next-line no-control-regex
  if (!/^[\x00-\x7f]+$/.test(program)) {
    throw new TypeError(
      'bolyraGate: `program` must be non-empty ASCII — it enters the receipt ' +
        'instance preimage domain (spec/receipt-instance-binding-v1.md §3.1)',
    );
  }
  const headerName = (options.header ?? BOLYRA_AUTHORIZATION_HEADER).toLowerCase();
  if (headerName === 'authorization') {
    throw new TypeError(
      'bolyraGate: `header` must not be "Authorization" — MPP\'s payment credential ' +
        'already rides that header; use a distinct header (default x-bolyra-authorization)',
    );
  }
  const enforce = options.enforce ?? 'always';
  const amountToUsd = options.amountToUsd ?? defaultAmountToUsd;
  // Exactly one clock: `now` (seconds) or `nowMs` (milliseconds). Each
  // derives from the other so there is a single time source; `nowMs` also
  // drives the ms-precision `decisionAt` in receipt instance binding.
  if (options.now !== undefined && options.nowMs !== undefined) {
    throw new TypeError(
      'bolyraGate: pass exactly one clock — `now` (seconds) or `nowMs` (milliseconds), not both',
    );
  }
  const secondsClock = options.now;
  const nowMs = options.nowMs ?? (secondsClock !== undefined ? () => secondsClock() * 1000 : Date.now);
  const now = secondsClock ?? (() => Math.floor(nowMs() / 1000));
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
    | { outcome: 'deny'; verdict: DenyVerdict; response: Response }
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
    // One timestamp per decision (spec §3.2), sampled fail-closed: a throwing
    // injected clock becomes an internal_error denial below, never an escape.
    let decisionMs: number | undefined;
    try {
      const sampled = nowMs();
      // Valid = finite, within Date's representable range, AND the derived
      // unix seconds are a positive integer — the EVC schema's now_unix has
      // exclusiveMinimum: 0, so sub-second epoch values (floor → 0) are as
      // invalid as negatives. Else new Date(...).toISOString() throws or the
      // verifier sees a bogus clock.
      decisionMs =
        Number.isFinite(sampled) && Math.floor(sampled / 1000) >= 1 && sampled <= 8.64e15
          ? sampled
          : undefined;
    } catch {
      decisionMs = undefined;
    }
    const decisionAt = decisionMs !== undefined ? new Date(decisionMs).toISOString() : undefined;

    // Instance construction must never throw out of the gate: computeInstanceRef
    // rejects out-of-domain preimages by design, and a receipt is emitted on
    // EVERY path — so a failed build degrades to an instance-less receipt.
    const tryInstance = (
      facts: DecisionReceiptFacts,
    ): ReturnType<typeof buildDecisionInstance> | undefined => {
      try {
        return buildDecisionInstance(instanceFactsFrom(facts));
      } catch {
        return undefined;
      }
    };

    // Receipt-sink failure is a host fault and MUST become a 500 internal_error
    // denial on every path — allow, ordinary deny, and a first emission that
    // happens inside the outer catch — without the sink ever being invoked a
    // second time. (Reviewer finding: before 0.5.0 an onReceipt throw inside
    // denyWith re-entered the outer catch, which called denyWith again, and
    // the SECOND throw escaped as a plain Error.) `emit` reports whether the
    // sink accepted the receipt; once it has failed it is never called again.
    //
    // The sink contract is SYNCHRONOUS. A sink that returns a Promise (an
    // `async` function) is a failure too: its rejection would land after the
    // decision and could never fail this request, so it is treated as
    // undelivered and the request denies. The returned promise gets a no-op
    // rejection handler so the host sees no unhandled rejection.
    type SinkFailure = 'threw' | 'async';
    let sinkFailure: SinkFailure | undefined;
    const emit = (signed: SignedReceipt): 'ok' | SinkFailure => {
      if (sinkFailure !== undefined) return sinkFailure;
      try {
        const returned: unknown = options.onReceipt?.(signed);
        if (typeof (returned as { then?: unknown } | null | undefined)?.then === 'function') {
          Promise.resolve(returned).catch(() => {});
          sinkFailure = 'async';
          return 'async';
        }
        return 'ok';
      } catch {
        sinkFailure = 'threw';
        return 'threw';
      }
    };
    const SINK_FAILED: DenyVerdict = deny('internal_error', 'authorization receipt sink failed');
    const SINK_ASYNC: DenyVerdict = deny(
      'internal_error',
      'onReceipt must be synchronous: it returned a Promise, so its failures could not fail this request',
    );
    const sinkVerdict = (failure: SinkFailure): DenyVerdict =>
      failure === 'async' ? SINK_ASYNC : SINK_FAILED;

    const denyWith = (verdict: DenyVerdict): {
      outcome: 'deny';
      verdict: DenyVerdict;
      response: Response;
    } => {
      const facts: DecisionReceiptFacts = {
        request: requestContext,
        tier: tier ?? ('small' as const),
        amountUsd,
        decisionAt: decisionAt ?? '',
        bundle: parsedBundle,
        denial: verdict,
      };
      // The instance claim is attached only when it would be TRUE: the spend
      // facts are real (route amount resolved to a tier) and the clock
      // produced a decision timestamp. Early denials (e.g.
      // missing_authorization) predate the action facts — binding an
      // instance over placeholders would claim more than the gate knows.
      const instance =
        tier !== undefined && decisionAt !== undefined ? tryInstance(facts) : undefined;
      const signed = receiptSigner.sign(buildDecisionReceiptInput(facts), instance);
      // If the sink failed on this emission — or had already failed — the decision
      // is internal_error, whatever code we were about to return.
      const emitted = emit(signed);
      const final = emitted === 'ok' ? verdict : sinkVerdict(emitted);
      return { outcome: 'deny', verdict: final, response: denyResponse(final) };
    };

    try {
      // 0. A dead clock is a host fault: fail closed before any decision.
      if (decisionMs === undefined) {
        return denyWith(deny('internal_error', 'gate clock failed'));
      }

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
      // now_unix derives from the SAME sampled instant as decisionAt, so the
      // verifier's clock and the receipt's instance timestamp agree in audit.
      const verifierRequest: VerifierRequest = {
        version: 1,
        bundle: bundleString,
        request: requestContext,
        now_unix: Math.floor(decisionMs / 1000),
      };
      const outcome = await dispatch(verifierRequest);
      parsedBundle = outcome.parsedBundle;
      if (outcome.verdict.verdict === 'deny') {
        return denyWith(outcome.verdict);
      }

      // 5. Build the allow receipt's instance block BEFORE burning any nonce:
      //    if construction fails (host fault, internal_error), the
      //    presentation must remain replayable for the retry — denying after
      //    reservation would turn the retry into a bogus nonce_replayed.
      //    Host faults do not burn nonces, except an undeliverable allow
      //    receipt (see step 7 below).
      const allowFacts: DecisionReceiptFacts = {
        request: requestContext,
        tier,
        amountUsd,
        // Defined here: step 0 already denied the request if the clock failed.
        decisionAt: decisionAt as string,
        bundle: parsedBundle,
      };
      const allowInstance = tryInstance(allowFacts);
      if (allowInstance === undefined) {
        return denyWith(
          deny('internal_error', 'receipt instance binding could not be constructed'),
        );
      }

      // 6. Host nonce mode (spec §7.3): reserve-before-act every consumed
      //    nonce; a reservation conflict means the presentation was replayed.
      //    The reservation timestamp is the SAME sampled decision instant —
      //    one clock read per decision, no drift under injected clocks.
      const consumeNonces = outcome.verdict.consume_nonces;
      if (consumeNonces !== undefined && consumeNonces.length > 0) {
        if (!(await nonceStore.reserve(consumeNonces, Math.floor(decisionMs / 1000)))) {
          return denyWith(deny('nonce_replayed', 'authorization presentation was already used'));
        }
      }

      // 7. Allow: sign the decision receipt and stash for the verify hook.
      const signed = receiptSigner.sign(buildDecisionReceiptInput(allowFacts), allowInstance);
      const emitted = emit(signed);
      if (emitted !== 'ok') {
        // The allow receipt could not be delivered: fail closed, never allow.
        // The nonce was reserved at step 6, before this emission, and
        // NonceStore has no release API, so the client's retry of the same
        // presentation denies nonce_replayed. This is the ONE host fault that
        // consumes a nonce, deliberately: a receipt that cannot be delivered
        // must not coexist with an allow.
        // The per-gate hash chain advances by the undelivered allow link and
        // then the truthful deny link that denyWith signs.
        return denyWith(sinkVerdict(emitted)); // emit() is latched; denyWith returns the sink verdict
      }

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
        // Throw, never return: mppx turns a returned non-402 Response into
        // outer status 200 and the application runs its action.
        throw new BolyraDeniedError(result.verdict, result.response);
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
