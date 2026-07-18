/**
 * The demo's composition seam: wrap a Stripe agent-toolkit style spend tool
 * so a Bolyra spend mandate is verified BEFORE the tool executes.
 *
 * Stripe's toolkit exposes no pre-spend authorization hook — `getTools()`
 * returns `{ description, execute }` tool definitions and `execute` goes
 * straight to the Stripe API. So the honest seam is to wrap the tool: the
 * guarded `execute` runs the Bolyra authorization pipeline first and only
 * delegates to the underlying (here: stubbed) Stripe tool on an allow.
 *
 * Everything on the authorization path is REAL shipped Bolyra code:
 *
 *   1. `requiredTierForUsdAmount` / `tierCapability` (@bolyra/mpp) map the
 *      requested amount to the financial tier it needs.
 *   2. `verifyClassical` (@bolyra/mpp) verifies the operator's EdDSA-Poseidon
 *      binding signature over the mandate, the trust anchor, expiry, the
 *      audience/model binding, and that the signed capabilities cover the
 *      tier this spend requires. This is the same verifier the shipped
 *      `bolyraGate` uses.
 *   3. `authContextToStripeACPContext` + `verifyStripeACPSpend`
 *      (@bolyra/payment-protocols) enforce the Stripe ACP per-transaction
 *      cap (strict `< $100` for the small tier), currency match, and
 *      integer-minor-unit amount rules — defense in depth behind the
 *      mandate check.
 *   4. `createGateReceiptSigner` (@bolyra/mpp, backed by @bolyra/receipts)
 *      signs a hash-chained ES256K receipt for EVERY decision, allow and
 *      deny.
 *
 * Only the wrapped tool itself (stripe-toolkit-stub.ts) is a mock.
 */

import {
  parseBundle,
  requiredTierForUsdAmount,
  tierCapability,
  verifyClassical,
} from '@bolyra/mpp';
import type {
  GateReceiptSigner,
  OperatorKey,
  ParsedBundle,
  VerifierRequestContext,
} from '@bolyra/mpp';
import {
  authContextToStripeACPContext,
  verifyStripeACPSpend,
} from '@bolyra/payment-protocols';
import type { BolyraVerifiedContext } from '@bolyra/payment-protocols';
import { canonicalize } from '@bolyra/receipts';
import type { CommerceReceiptInput, SignedReceipt } from '@bolyra/receipts';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Input a spend tool accepts — Stripe convention: integer minor units. */
export interface SpendToolInput {
  /** Amount in minor units (cents for USD). */
  amount: number;
  /** ISO 4217 currency, lowercase (Stripe convention). */
  currency: string;
}

/**
 * The minimal spend-tool surface the guard composes with — the
 * `{ description, execute }` shape `@stripe/agent-toolkit` tools have. The
 * guard depends ONLY on this, so swapping the demo stub for a real toolkit
 * tool type-checks; demo conveniences like the stub's call log stay on the
 * stub side.
 */
export interface SpendToolLike<PI extends { id: string } = { id: string }> {
  /** Optional — toolkit tools registered as `{ toolName: tool }` maps often omit it. */
  name?: string;
  description: string;
  execute(input: SpendToolInput): Promise<PI>;
}

export interface GuardOptions {
  /** The bvp/1 presentation issued by `issueMandate` (the spend mandate). */
  mandate: string;
  /** Operator keys the verifier trusts as mandate issuers (fail-closed). */
  trustedOperators: OperatorKey[];
  /** Request identity — must match the signed binding byte-for-byte. */
  agentName: string;
  /** The payee / audience the mandate was issued for (`project_key`). */
  audience: string;
  /** The model the credential binds to. */
  model: string;
  /** Binding program discriminator. Default "mpp" (issueMandate's default). */
  program?: string;
  /** Signs one hash-chained receipt per decision (allow AND deny). */
  receiptSigner: GateReceiptSigner;
  /** Merchant label recorded in receipts. */
  merchant: string;
  /** DID network segment. Default "base-sepolia". */
  network?: string;
  /** Clock override for tests. Default: Date.now. */
  now?: () => number;
}

export type GuardedSpendResult<PI = { id: string }> =
  | {
      authorized: true;
      /** Tier the spend was authorized under. */
      tier: string;
      /** ACP per-transaction cap that was enforced (minor units). */
      capChecked: number;
      /** Whatever the wrapped tool returned (in this demo: a MOCK object). */
      paymentIntent: PI;
      receipt: SignedReceipt;
    }
  | {
      authorized: false;
      /** Which real check denied: the mandate verifier or the ACP cap. */
      deniedBy: 'mandate' | 'stripe-acp';
      reason: string;
      receipt: SignedReceipt;
    };

/** The payment-intent type a spend tool's `execute` resolves to. */
export type ToolPaymentIntent<T> = T extends SpendToolLike<infer PI> ? PI : never;

/**
 * The wrapped tool: everything the original tool carried (e.g. `parameters`
 * for Vercel AI SDK registration — preserved by spread), with `execute`
 * replaced by the guarded version.
 */
export type GuardedSpendTool<T extends SpendToolLike> = Omit<T, 'execute'> & {
  execute(input: SpendToolInput): Promise<GuardedSpendResult<ToolPaymentIntent<T>>>;
};

/**
 * Thrown when the wrapped tool itself fails AFTER authorization. The signed
 * allow receipt is attached — the authorization decision is on the audit
 * trail even when the downstream Stripe call errors.
 */
export class SpendToolExecutionError extends Error {
  constructor(
    public readonly receipt: SignedReceipt,
    public readonly cause: unknown,
  ) {
    super(
      `spend tool failed after authorization (receipt ${receipt.id} records the allow decision): ` +
        (cause instanceof Error ? cause.message : String(cause)),
    );
    this.name = 'SpendToolExecutionError';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Integer-only minor-units → exact USD decimal string ("2500" → "25.00").
 * Never goes through floats — mirrors @bolyra/mpp's exact-decimal discipline.
 */
export function centsToUsdString(cents: number): string {
  if (!Number.isSafeInteger(cents) || cents < 0) {
    throw new TypeError(`amount must be a non-negative safe integer in cents, got ${cents}`);
  }
  const dollars = Math.floor(cents / 100);
  const rem = cents % 100;
  return `${dollars}.${String(rem).padStart(2, '0')}`;
}

function didFromDec(network: string, decimal: string): string {
  return `did:bolyra:${network}:${BigInt(decimal).toString(16).padStart(64, '0')}`;
}

function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Build the receipt input for one spend decision. Modeled on @bolyra/mpp's
 * `buildDecisionReceiptInput`, with the commerce block carrying the Stripe
 * rail instead of MPP (this decision fronts a Stripe spend, not an MPP
 * payment). Demo-local glue — composes shipped receipt primitives only.
 *
 * `intentHash` is a bare 64-char sha256 hex over the canonical spend facts
 * (the `bolyra receipts verify` CLI enforces /^[0-9a-fA-F]{64}$/), identical
 * in form for allow and deny receipts.
 */
function buildSpendReceiptInput(args: {
  request: VerifierRequestContext;
  bundle: ParsedBundle | undefined;
  network: string;
  merchant: string;
  amountCents: number;
  currency: string;
  allowed: boolean;
  reasonCode?: string;
}): CommerceReceiptInput {
  const { request, bundle, network } = args;
  const operator = bundle?.agent.credential.operator_pubkey;
  const envelope = bundle?.agent.envelope;
  const scopeCommitment = envelope?.publicSignals[2] ?? '0';

  return {
    rootDid: operator ? didFromDec(network, operator.x) : 'did:bolyra:anonymous',
    actingDid:
      scopeCommitment !== '0'
        ? didFromDec(network, scopeCommitment)
        : `did:bolyra:agent:${request.agent_name}`,
    credentialCommitment: scopeCommitment,
    effectiveCommitment: scopeCommitment,
    allowed: args.allowed,
    ...(args.reasonCode !== undefined && { reasonCode: args.reasonCode }),
    score: args.allowed ? 1 : 0,
    permissionBitmask: bundle?.agent.credential.permission_bitmask ?? '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: envelope?.proof ?? [] },
    humanPublicSignals: [],
    agentPublicSignals: envelope?.publicSignals ?? [],
    bundleVersion: 1,
    nonce: BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString(),
    commerce: {
      rail: 'stripe-acp',
      amount: args.amountCents,
      currency: args.currency.toUpperCase(),
      merchant: args.merchant,
      intentHash: sha256Hex(
        canonicalize({
          audience: request.project_key,
          amountCents: args.amountCents,
          currency: args.currency,
          decision: args.allowed ? 'allow' : 'deny',
        }),
      ),
    },
  };
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/**
 * Wrap a Stripe-toolkit-style spend tool with Bolyra spend-mandate
 * authorization. The wrapped tool is only invoked after BOTH real checks
 * pass; a denial short-circuits before any Stripe call.
 */
export function guardSpendTool<T extends SpendToolLike>(
  tool: T,
  options: GuardOptions,
): GuardedSpendTool<T> {
  type PI = ToolPaymentIntent<T>;
  const program = options.program ?? 'mpp';
  const network = options.network ?? 'base-sepolia';
  const now = options.now ?? (() => Date.now());

  return {
    // Preserve every field the original tool carries (parameters, schema,
    // etc.) so the wrapped tool still registers with the host framework.
    ...tool,
    description: `${tool.description} (guarded by a Bolyra spend mandate)`,

    async execute(input: SpendToolInput): Promise<GuardedSpendResult<PI>> {
      // Parse once for receipt subject data. Verification below re-parses
      // internally — parse failures here fall through to a mandate denial.
      let parsed: ParsedBundle | undefined;
      try {
        parsed = parseBundle(options.mandate);
      } catch {
        parsed = undefined;
      }

      // Malformed runtime input must fail closed WITH a receipt — never throw.
      const safeCurrency =
        typeof input.currency === 'string' && input.currency.trim() !== ''
          ? input.currency
          : undefined;
      const safeAmount = Number.isSafeInteger(input.amount) && input.amount >= 0
        ? input.amount
        : 0;

      const sign = (
        request: VerifierRequestContext,
        allowed: boolean,
        reasonCode?: string,
      ): SignedReceipt =>
        options.receiptSigner.sign(
          buildSpendReceiptInput({
            request,
            bundle: parsed,
            network,
            merchant: options.merchant,
            amountCents: safeAmount,
            currency: (safeCurrency ?? 'unknown').toLowerCase(),
            allowed,
            ...(reasonCode !== undefined && { reasonCode }),
          }),
        );

      const baseRequest: VerifierRequestContext = {
        agent_name: options.agentName,
        project_key: options.audience,
        program,
        model: options.model,
        granted_capabilities: [],
      };

      // ── Check 0: input sanity (before any tier math) ─────────────────────
      if (safeCurrency === undefined) {
        return {
          authorized: false,
          deniedBy: 'stripe-acp',
          reason: `invalid currency: ${String(input.currency)} (must be a non-empty string)`,
          receipt: sign(baseRequest, false, 'invalid_currency'),
        };
      }
      let amountUsd: string;
      try {
        amountUsd = centsToUsdString(input.amount);
      } catch (err) {
        return {
          authorized: false,
          deniedBy: 'stripe-acp',
          reason: err instanceof Error ? err.message : String(err),
          receipt: sign(baseRequest, false, 'invalid_amount'),
        };
      }

      // ── Check 1: mandate covers the tier this amount requires ────────────
      // (REAL: @bolyra/mpp verifyClassical — operator signature, trust
      // anchor, expiry, audience/model binding, capability subset.)
      const requiredTier = requiredTierForUsdAmount(amountUsd);
      const request: VerifierRequestContext = {
        ...baseRequest,
        granted_capabilities: [tierCapability(requiredTier)],
      };
      const verdict = await verifyClassical(
        {
          version: 1,
          bundle: options.mandate,
          request,
          now_unix: Math.floor(now() / 1000),
        },
        options.trustedOperators,
      );
      if (verdict.verdict === 'deny') {
        return {
          authorized: false,
          deniedBy: 'mandate',
          reason: `${verdict.code}: ${verdict.message}`,
          receipt: sign(request, false, verdict.code),
        };
      }

      // ── Check 2: Stripe ACP per-transaction cap ──────────────────────────
      // (REAL: @bolyra/payment-protocols — the verified mandate is mapped
      // into a Stripe ACP context and the spend is checked against the
      // strict tier cap, currency, and minor-unit rules.)
      //
      // `parsed` is non-undefined here: verifyClassical allowed, so the
      // bundle parsed. The scope commitment in publicSignals[2] was
      // recomputed from the revealed credential by verifyClassical, and the
      // permission bitmask was cross-checked against the SIGNED tier
      // capabilities — this context restates facts the verifier established.
      const cred = parsed!.agent.credential;
      const verifiedCtx: BolyraVerifiedContext = {
        verified: true, // anchored to the verifyClassical allow above
        score: 100, // classical verification is pass/fail — no partial score
        did: didFromDec(network, cred.operator_pubkey.x), // root = issuing operator
        permissionBitmask: BigInt(cred.permission_bitmask),
        chainDepth: 0, // operator → agent, no delegation chain hops
        effectiveCommitment: parsed!.agent.envelope.publicSignals[2] ?? '0',
        warnings: [],
      };
      // One canonical spend input for the ACP check, the receipt, and the
      // tool call — a mixed-case "USD" must not authorize as usd and then
      // reach the real Stripe tool in non-canonical form.
      const canonicalInput: SpendToolInput = {
        amount: input.amount,
        currency: safeCurrency.toLowerCase(),
      };
      const acpCtx = authContextToStripeACPContext(verifiedCtx, network, 'usd');
      const decision = verifyStripeACPSpend(
        acpCtx,
        canonicalInput.amount,
        canonicalInput.currency,
        'authorize',
      );
      if (!decision.allowed) {
        return {
          authorized: false,
          deniedBy: 'stripe-acp',
          reason: decision.reason ?? 'denied by Stripe ACP spend check',
          receipt: sign(request, false, 'acp_cap'),
        };
      }

      // ── Authorized: sign the decision receipt, THEN run the (MOCK) tool ──
      // The receipt records the AUTHORIZATION decision, so it is signed
      // before execution: a downstream Stripe failure must not erase the
      // audit fact that the spend was authorized.
      const receipt = sign(request, true);
      let paymentIntent: PI;
      try {
        paymentIntent = (await tool.execute(canonicalInput)) as PI;
      } catch (err) {
        throw new SpendToolExecutionError(receipt, err);
      }
      return {
        authorized: true,
        tier: decision.tier,
        capChecked: decision.capChecked,
        paymentIntent,
        receipt,
      };
    },
  };
}
