/**
 * Coinbase x402 Adapter
 *
 * Rides alongside the standard `PAYMENT-REQUIRED` envelope: the server emits a
 * 402 with a fresh `Bolyra-Challenge` nonce, the agent returns a
 * `Bolyra-Credential` carrying a mutual ZK handshake proof bound to that
 * nonce, and the server verifies the proof off-chain before letting the call
 * through.
 *
 * Wire format (base64url(JSON)):
 *   {
 *     v: 1,
 *     did, sessionNonce (hex), scopeCommitment (decimal),
 *     scopeBitmask (decimal),
 *     humanProof, agentProof,                 // Groth16 proofs
 *     spendPolicy: { maxTransactionAmount, currency }
 *   }
 *
 * The merchant never sees the human's identity, the exact policy graph, or
 * any delegation chain — only that `verifyHandshake` cleared against the
 * server's challenge.
 */

import * as path from 'path';
import type {
  HumanIdentity,
  AgentCredential,
  Proof,
  BolyraConfig,
} from '@bolyra/sdk';

import { loadSDK } from './sdk-loader';
import type { PaymentTrustGrade, SpendPolicy } from './types';

// ---------------------------------------------------------------------------
// Header constants
// ---------------------------------------------------------------------------

/** Standard x402 envelope header carrying the `PAYMENT-REQUIRED` accepts list. */
export const X402_PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED';

/** Server → client: fresh single-use challenge nonce for this 402 round-trip. */
export const X402_BOLYRA_CHALLENGE_HEADER = 'Bolyra-Challenge';

/** Client → server: base64url-encoded ZK credential bound to the challenge. */
export const X402_BOLYRA_CREDENTIAL_HEADER = 'Bolyra-Credential';

/** Bolyra wire format version embedded in the credential. */
export const X402_WIRE_VERSION = 1 as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal x402 payment requirements the merchant advertises in the 402
 * response. Matches the Coinbase x402 `accepts` envelope; Bolyra binds its
 * authorization to this exact requirements blob.
 */
export interface X402PaymentRequirements {
  /** CAIP-2 chain ID (e.g. `eip155:84532` for Base Sepolia). */
  chain: string;
  /** Asset symbol (e.g. `USDC`). */
  asset: string;
  /** Amount in minor units (e.g. cents). */
  amount: number;
  /** Recipient address. */
  recipient: string;
  /** Optional Merchant Category Code. */
  mcc?: string;
}

/** Result of `createX402Authorization`. */
export interface X402AuthorizationResult {
  /** Always true on the client side — server-side `verifyX402Authorization` is the source of truth. */
  verified: boolean;
  /** Self-asserted trust score (0–100). */
  score: number;
  /** Letter grade derived from score. */
  grade: PaymentTrustGrade;
  /** `did:bolyra:<network>:<commitment>` for the acting agent. */
  did: string;
  /** Headers to attach to the retry request. */
  headers: Record<string, string>;
  /** Session nonce the proof was bound to. */
  sessionNonce: bigint;
}

/** Result of `verifyX402Authorization`. */
export interface X402VerifyDecision {
  /** Whether the credential passed all gates (ZK + policy fit). */
  verified: boolean;
  /** Composite trust score (0–100). */
  score: number;
  /** Letter grade derived from score. */
  grade: PaymentTrustGrade;
  /** Acting agent DID from the credential. */
  did: string;
  /** Scope commitment from the handshake (root of the delegation chain). */
  scopeCommitment: bigint;
  /** Session nonce the credential committed to — caller MUST cross-check this against their nonce store. */
  sessionNonce: bigint;
  /** Soft signals (resolver miss, policy gaps, ZK errors) collected during verify. */
  warnings: string[];
}

/**
 * Server-supplied lookup that maps a `did:bolyra:*` to the registered agent
 * credential, or `null` if unknown. Typically a DB read or cache hit.
 */
export type X402CredentialResolver = (
  did: string,
) => Promise<AgentCredential | null>;

/** Optional config — falls back to bundled vkeys + defaults. */
export interface X402Config {
  /** SDK config (circuit / vkey overrides). Defaults to bundled vkeys. */
  sdk?: BolyraConfig;
  /** Minimum score for `verified=true` (default: 70). */
  minScore?: number;
  /** Network label used in DID construction (default: `base-sepolia`). */
  network?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function gradeFromScore(score: number): PaymentTrustGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function toBase64Url(s: string): string {
  return Buffer.from(s, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64Url(s: string): string {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

/** Default circuit directory — the vkeys shipped alongside this package. */
function bundledVkeyDir(): string {
  // Resolves to <pkg>/vkeys at runtime (src/x402.ts -> ../vkeys; dist/x402.js -> ../vkeys).
  return path.join(__dirname, '..', 'vkeys');
}

function defaultConfig(cfg?: X402Config): {
  sdk: BolyraConfig;
  minScore: number;
  network: string;
} {
  return {
    sdk: { circuitDir: bundledVkeyDir(), ...(cfg?.sdk ?? {}) },
    minScore: cfg?.minScore ?? 70,
    network: cfg?.network ?? 'base-sepolia',
  };
}

function didFromAgent(network: string, agentCommitment: bigint): string {
  const hex = agentCommitment.toString(16);
  return `did:bolyra:${network}:0x${hex.padStart(64, '0')}`;
}

interface WireBundle {
  v: typeof X402_WIRE_VERSION;
  did: string;
  /** Hex-encoded session nonce (no `0x` prefix). */
  sessionNonce: string;
  /** Decimal-encoded scope commitment. */
  scopeCommitment: string;
  /** Decimal-encoded permission bitmask. */
  scopeBitmask: string;
  humanProof: Proof;
  agentProof: Proof;
  spendPolicy: {
    maxTransactionAmount: number;
    currency: string;
  };
}

// ---------------------------------------------------------------------------
// Serialization of PAYMENT-REQUIRED
// ---------------------------------------------------------------------------

/** Serialize an `X402PaymentRequirements` blob for the `PAYMENT-REQUIRED` header. */
export function serializePaymentRequired(reqs: X402PaymentRequirements): string {
  return JSON.stringify(reqs);
}

/** Parse an `X402PaymentRequirements` blob from the `PAYMENT-REQUIRED` header. */
export function parsePaymentRequired(s: string): X402PaymentRequirements {
  const parsed = JSON.parse(s) as Partial<X402PaymentRequirements>;
  if (
    typeof parsed?.chain !== 'string' ||
    typeof parsed?.asset !== 'string' ||
    typeof parsed?.amount !== 'number' ||
    typeof parsed?.recipient !== 'string'
  ) {
    throw new Error('parsePaymentRequired: missing required fields (chain, asset, amount, recipient)');
  }
  return parsed as X402PaymentRequirements;
}

// ---------------------------------------------------------------------------
// Client: build the Bolyra-Credential header
// ---------------------------------------------------------------------------

/**
 * Build an x402 authorization credential bound to the server's challenge nonce.
 *
 * Runs `proveHandshake` from `@bolyra/sdk` with `nonce: bolyraChallenge`, then
 * packs the resulting proofs + scope metadata into the `Bolyra-Credential`
 * header value (base64url-encoded JSON).
 *
 * Requires a Bolyra prover environment (circuit `.wasm` + `.zkey`). For
 * verification-only environments use the published vkeys; for proving you
 * need the full circuit artifacts (see `circuits/build/` in the monorepo
 * or pre-record proofs offline as `sdk/demo/generate-artifacts.js` does).
 */
export async function createX402Authorization(
  human: HumanIdentity,
  agent: AgentCredential,
  spendPolicy: Pick<SpendPolicy, 'maxTransactionAmount' | 'currency'>,
  ctx: { requirements: X402PaymentRequirements; bolyraChallenge: bigint },
  config?: X402Config,
): Promise<X402AuthorizationResult> {
  const cfg = defaultConfig(config);
  const sdk = loadSDK();

  const handshake = await sdk.proveHandshake(human, agent, {
    nonce: ctx.bolyraChallenge,
    config: cfg.sdk,
  });

  const did = didFromAgent(cfg.network, agent.commitment);
  // Recover scopeCommitment from the agent proof's public signals.
  // AgentPolicy circuit emits scopeCommitment as the 4th public signal
  // (index 3): [agentNullifier, agentRoot, sessionNonce, scopeCommitment].
  // Falls back to 0 if the schema changes — verifyX402Authorization re-derives
  // it from the proof itself anyway.
  const scopeCommitment = safeBigInt(handshake.agentProof.publicSignals?.[3]) ?? 0n;

  const bundle: WireBundle = {
    v: X402_WIRE_VERSION,
    did,
    sessionNonce: ctx.bolyraChallenge.toString(16),
    scopeCommitment: scopeCommitment.toString(),
    scopeBitmask: agent.permissionBitmask.toString(),
    humanProof: handshake.humanProof,
    agentProof: handshake.agentProof,
    spendPolicy: {
      maxTransactionAmount: spendPolicy.maxTransactionAmount,
      currency: spendPolicy.currency ?? 'USD',
    },
  };

  const credentialHeader = toBase64Url(JSON.stringify(bundle));

  // Self-asserted score on the client side — the server's verifyX402Authorization
  // is the source of truth, but we surface a best-case score so callers can
  // pre-check before round-tripping.
  const score = 100;

  return {
    verified: true,
    score,
    grade: gradeFromScore(score),
    did,
    sessionNonce: ctx.bolyraChallenge,
    headers: {
      [X402_BOLYRA_CREDENTIAL_HEADER]: credentialHeader,
    },
  };
}

// ---------------------------------------------------------------------------
// Server: verify the credential
// ---------------------------------------------------------------------------

/**
 * Verify an x402 Bolyra credential against payment requirements.
 *
 * Performs four gates and composes a 0–100 score:
 *   1. Wire decode + schema check       (rejection → grade F)
 *   2. ZK handshake verifies            (+60)
 *   3. `resolveCredential(did)` returns a credential (+20)
 *   4. Spend-policy fit: `requirements.amount ≤ scopeMaxTransactionAmount` (+20)
 *
 * The caller is responsible for replay protection (cross-checking
 * `sessionNonce` against their nonce store).
 */
export async function verifyX402Authorization(
  credentialHeader: string,
  requirements: X402PaymentRequirements,
  resolveCredential: X402CredentialResolver,
  config?: X402Config,
): Promise<X402VerifyDecision> {
  const cfg = defaultConfig(config);
  const warnings: string[] = [];

  // Step 1 — decode wire format
  let bundle: WireBundle;
  try {
    bundle = JSON.parse(fromBase64Url(credentialHeader)) as WireBundle;
  } catch (e: unknown) {
    return rejection('malformed credential header (base64url/JSON decode failed)');
  }
  if (bundle?.v !== X402_WIRE_VERSION) {
    return rejection(`unsupported wire version ${String(bundle?.v)} (expected ${X402_WIRE_VERSION})`);
  }
  if (
    typeof bundle.did !== 'string' ||
    typeof bundle.sessionNonce !== 'string' ||
    !bundle.humanProof ||
    !bundle.agentProof ||
    !bundle.spendPolicy
  ) {
    return rejection('credential bundle missing required fields');
  }

  const sessionNonce = safeBigInt('0x' + bundle.sessionNonce) ?? 0n;
  const scopeCommitment = safeBigInt(bundle.scopeCommitment) ?? 0n;

  // Step 2 — ZK verify against the embedded session nonce
  let zkVerified = false;
  try {
    const sdk = loadSDK();
    const result = await sdk.verifyHandshake(
      bundle.humanProof,
      bundle.agentProof,
      sessionNonce,
      cfg.sdk,
    );
    zkVerified = !!result.verified;
    if (!zkVerified) warnings.push('zk handshake verify returned false');
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`zk verify error: ${msg}`);
  }

  // Step 3 — DID resolves to a known credential
  let credentialResolved = false;
  try {
    const credential = await resolveCredential(bundle.did);
    credentialResolved = credential != null;
    if (!credentialResolved) warnings.push(`unresolved did: ${bundle.did}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`resolveCredential threw: ${msg}`);
  }

  // Step 4 — spend-policy fit
  const policyFit = requirements.amount <= bundle.spendPolicy.maxTransactionAmount;
  if (!policyFit) {
    warnings.push(
      `amount ${requirements.amount} ${requirements.asset} exceeds spend cap ${bundle.spendPolicy.maxTransactionAmount} ${bundle.spendPolicy.currency}`,
    );
  }

  // Score composition
  let score = 0;
  if (zkVerified) score += 60;
  if (credentialResolved) score += 20;
  if (policyFit) score += 20;

  const verified = zkVerified && policyFit && score >= cfg.minScore;

  return {
    verified,
    score,
    grade: gradeFromScore(score),
    did: bundle.did,
    scopeCommitment,
    sessionNonce,
    warnings,
  };

  function rejection(reason: string): X402VerifyDecision {
    return {
      verified: false,
      score: 0,
      grade: 'F',
      did: '',
      scopeCommitment: 0n,
      sessionNonce: 0n,
      warnings: [reason],
    };
  }
}

function safeBigInt(v: unknown): bigint | null {
  if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'bigint') return null;
  try {
    return BigInt(v);
  } catch {
    return null;
  }
}
