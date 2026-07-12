/**
 * @bolyra/mpp — shared types.
 *
 * The verdict + denial-code taxonomy is the External Verifier Contract v1
 * wire format (spec/external-verifier-contract-v1.md §3, §9), copied here so
 * this package has no dependency on @bolyra/cli. Do not add, remove, or
 * rename a DenyCode member without a spec change — the one extension is
 * `missing_authorization`, a HOST-side (gate-local) code for "the request
 * carried no authorization header at all", which by definition never crosses
 * the verifier wire.
 */

import type { SignedReceipt } from '@bolyra/receipts';

/** The spec §9 denial taxonomy — exactly these 15 codes. */
export type EvcDenyCode =
  | 'malformed_input'
  | 'unsupported_version'
  | 'invalid_bundle'
  | 'invalid_proof'
  | 'untrusted_root'
  | 'delegation_invalid'
  | 'invalid_signature'
  | 'request_mismatch'
  | 'model_mismatch'
  | 'unknown_capability'
  | 'scope_exceeded'
  | 'expired'
  | 'nonce_missing'
  | 'nonce_replayed'
  | 'internal_error';

/** EVC codes plus the gate-local "no header presented" code. */
export type DenyCode = EvcDenyCode | 'missing_authorization';

/** Spec §3.2: instruction to burn a one-time nonce (host nonce mode). */
export interface ConsumeNonce {
  issuer_key: string;
  nonce: string;
  retain_until: number;
}

/** Spec §3.1 allow verdict. */
export interface AllowVerdict {
  verdict: 'allow';
  consume_nonces?: ConsumeNonce[];
  /** Spec §3.5 verifier self-description. */
  kind?: string;
}

/** Spec §3.2 deny verdict. */
export interface DenyVerdict {
  verdict: 'deny';
  code: DenyCode;
  message: string;
  kind?: string;
  detail?: Record<string, unknown>;
}

export type Verdict = AllowVerdict | DenyVerdict;

/** Build an allow verdict; `consume_nonces` is omitted when empty. */
export function allow(consumeNonces?: ConsumeNonce[]): AllowVerdict {
  return consumeNonces === undefined || consumeNonces.length === 0
    ? { verdict: 'allow' }
    : { verdict: 'allow', consume_nonces: consumeNonces };
}

/** Build a deny verdict; `detail` is included only when provided. */
export function deny(
  code: DenyCode,
  message: string,
  detail?: Record<string, unknown>,
): DenyVerdict {
  return detail === undefined
    ? { verdict: 'deny', code, message }
    : { verdict: 'deny', code, message, detail };
}

/**
 * Shared denial signal for gate modules: throw a `VerifyDenial` when a check
 * fails; the gate converts it to a deny verdict + Problem Details response.
 * Same pattern as the `bolyra verify` reference verifier.
 */
export class VerifyDenial extends Error {
  constructor(
    public readonly code: DenyCode,
    message: string,
    public readonly detail?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'VerifyDenial';
  }

  toVerdict(): DenyVerdict {
    return deny(this.code, this.message, this.detail);
  }
}

export function isVerifyDenial(err: unknown): err is VerifyDenial {
  return err instanceof VerifyDenial;
}

/** The spec §2.1 request context the gate builds for a verifier. */
export interface VerifierRequestContext {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  granted_capabilities: string[];
}

/** The full spec §2.1 verifier request. */
export interface VerifierRequest {
  version: 1;
  bundle: string;
  request: VerifierRequestContext;
  now_unix: number;
}

/** Decimal-string BabyJubjub public-key coordinate pair. */
export interface OperatorKey {
  x: string;
  y: string;
}

/** How the gate reaches a verifier. Default: in-process classical. */
export type VerifierConfig =
  /**
   * In-process classical (Bolyra Core) verification — the default. No ZK
   * dependency: nothing in this path loads snarkjs. `trustedOperators` is the
   * trust anchor and MUST be non-empty (fail-closed).
   */
  | { kind: 'classical'; trustedOperators: OperatorKey[] }
  /**
   * Spawn an External Verifier Contract v1 command (e.g. `bolyra verify`)
   * per spec §5/§7: one JSON request on stdin, one verdict on stdout,
   * host-owned timeout, fail-closed on every failure class.
   */
  | {
      kind: 'command';
      command: string;
      args?: string[];
      /** Host-owned timeout, spec §6 RECOMMENDED default 10 000 ms. */
      timeoutMs?: number;
      /** Cap on verifier stdout; overflow fails closed. Default 1 MiB. */
      maxStdoutBytes?: number;
    }
  /**
   * POST the spec §2.1 request to a hosted verifier endpoint that returns one
   * spec §3.4 verdict (e.g. the Bolyra hosted-verify design-partner preview).
   */
  | {
      kind: 'url';
      url: string;
      token?: string;
      timeoutMs?: number;
      /** Cap on the verdict response body; overflow fails closed. Default 1 MiB. */
      maxBodyBytes?: number;
    };

/**
 * Reserve-before-act nonce storage (EVC v1 §7.3) for verifiers in host nonce
 * mode. `reserve` MUST atomically reserve every entry and return `false` when
 * ANY entry was already reserved (the gate then denies `nonce_replayed`).
 * The default store is in-memory and single-process; multi-instance or
 * restart-surviving deployments MUST inject a shared, durable implementation
 * (e.g. Redis `SET NX`).
 */
export interface NonceStoreLike {
  reserve(entries: ConsumeNonce[], nowUnix: number): boolean | Promise<boolean>;
}

/** ES256K receipt signing key material (see @bolyra/receipts). */
export interface GateReceiptConfig {
  issuer?: string;
  keyId?: string;
  /** 0x-prefixed 32-byte secp256k1 private key. Omitted = ephemeral key. */
  privateKey?: string;
}

/** Options for {@link import('./gate').bolyraGate}. */
export interface BolyraGateOptions {
  /**
   * The audience/payee identifier this route accepts mandates for. Compared
   * BYTE-LITERALLY against the operator-signed binding's `project_key`
   * (spec §4.3) — a mandate signed for a different audience is denied
   * `request_mismatch` before any payment logic runs.
   */
  audience: string;
  /** Verifier backend. Default requires `{ kind: 'classical', trustedOperators }`. */
  verifier: VerifierConfig;
  /** Binding `program` discriminator. Default `"mpp"`. */
  program?: string;
  /**
   * Optional model pin. When set, the operator-signed binding must name this
   * model. When omitted, the binding's own `model` is echoed (identifying,
   * not restricting — see README "What is and isn't checked").
   */
  model?: string;
  /**
   * Resolve the route's payment amount to a decimal USD string/number for
   * tier mapping. Default: `options.amount` is treated as a decimal USD
   * amount (the `mppx.charge({ amount: '1' })` convention). Provide this when
   * the route's `amount` is in token base units or a non-USD currency.
   * Unresolvable amounts fail closed (`internal_error`).
   */
  amountToUsd?: (context: {
    amount: unknown;
    options: Record<string, unknown>;
  }) => string | number;
  /**
   * When to run the gate. `"always"` (default) also gates challenge-issuance
   * requests, so unauthorized agents never see a 402 challenge. `"payment"`
   * gates only requests that present a payment credential.
   */
  enforce?: 'always' | 'payment';
  /**
   * Request header carrying the presentation bundle. Default
   * `x-bolyra-authorization`. `Authorization` is rejected — MPP's payment
   * credential already rides that header.
   */
  header?: string;
  /**
   * Reserve-before-act nonce store for host-nonce-mode verifiers (EVC §7.3).
   * Default: in-memory, per-gate-instance — replay protection does NOT
   * survive restarts or span instances; inject a durable/shared store for
   * multi-instance deployments.
   */
  nonceStore?: NonceStoreLike;
  /** ES256K authorization-receipt signing. Ephemeral key when omitted. */
  receipts?: GateReceiptConfig;
  /** Sink for every signed decision receipt (allow AND deny). */
  onReceipt?: (receipt: SignedReceipt) => void;
  /** Clock override (unix seconds). Tests only. */
  now?: () => number;
}

/** Cumulative financial tiers from @bolyra/sdk's Permission model. */
export type FinancialTier = 'small' | 'medium' | 'unlimited';

/** An allow decision the gate stashes between preflight and verify. */
export interface GateDecision {
  tier: FinancialTier;
  capability: string;
  amountUsd: string;
  verifier: 'classical' | 'command' | 'url';
  request: VerifierRequestContext;
  receipt?: {
    payloadHash: string;
    signer: string;
    issuer: string;
    keyId: string;
    seq: number | undefined;
  };
}
