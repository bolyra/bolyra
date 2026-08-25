/**
 * Authorization-receipt signing — the @bolyra/gateway 0.5.0 receipt-signer
 * pattern: sign an ES256K receipt (via @bolyra/receipts) for EVERY gate
 * decision, allow and deny, hash-chained per gate instance.
 *
 * Key resolution order:
 *   1. `receipts.privateKey` from the gate options
 *   2. Ephemeral key generated when the gate is created (dev-friendly
 *      default). Receipts remain independently verifiable — `verifyReceipt()`
 *      recovers the signer address — but the address rotates per process, so
 *      production deployments should pin a key.
 *
 * Receipts are `kind: "bolyra.commerce"` with `commerce.rail = "mpp"`, so the
 * authorization receipt and MPP's own Payment-Receipt line up as the two
 * halves of the approved → paid audit trail (docs/mpp-authorization-companion.md).
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  canonicalize,
  computeInstanceRef,
  createCommerceReceipt,
  signReceipt,
  ReceiptChain,
} from '@bolyra/receipts';
import type {
  CommerceReceiptInput,
  InstancePreimage,
  ReceiptInstanceFields,
  ReceiptSignerConfig,
  SignedReceipt,
} from '@bolyra/receipts';
import type { ParsedBundle } from './bundle';
import type {
  DenyVerdict,
  FinancialTier,
  GateReceiptConfig,
  VerifierRequestContext,
} from './types';

const DEFAULT_ISSUER = 'bolyra-mpp-gate';
const DEFAULT_KEY_ID = 'k1';

/** A resolved gate receipt signer (one hash chain per gate instance). */
export interface GateReceiptSigner {
  issuer: string;
  keyId: string;
  alg: 'ES256K';
  /** Ethereum-style address recovered from the signing key. */
  signer: string;
  /** True when the key was generated at gate creation rather than configured. */
  ephemeral: boolean;
  /**
   * Sign one decision receipt. The optional `instance` block is attached to
   * the payload BEFORE signing, so the ES256K signature covers it
   * (spec/receipt-instance-binding-v1.md §3).
   */
  sign(input: CommerceReceiptInput, instance?: ReceiptInstanceFields): SignedReceipt;
}

/**
 * Resolve the gate's receipt signer. Throws at gate creation if a configured
 * private key is malformed (fail fast, not on the first request).
 */
export function createGateReceiptSigner(config: GateReceiptConfig = {}): GateReceiptSigner {
  const ephemeral = config.privateKey === undefined;
  const signerConfig: ReceiptSignerConfig = {
    issuer: config.issuer ?? DEFAULT_ISSUER,
    keyId: config.keyId ?? DEFAULT_KEY_ID,
    privateKey: config.privateKey ?? '0x' + randomBytes(32).toString('hex'),
  };

  // Derive the signer address by signing a throwaway probe payload — signed
  // OUTSIDE the chain so the first real receipt is the chain's genesis.
  const probe = signReceipt(createCommerceReceipt(probeInput(), signerConfig), signerConfig);

  const chain = new ReceiptChain();
  return {
    issuer: signerConfig.issuer,
    keyId: signerConfig.keyId,
    alg: 'ES256K',
    signer: probe.signature.signer,
    ephemeral,
    sign(input: CommerceReceiptInput, instance?: ReceiptInstanceFields): SignedReceipt {
      const payload = createCommerceReceipt(input, signerConfig);
      return chain.sign(
        instance !== undefined ? { ...payload, instance } : payload,
        signerConfig,
      );
    },
  };
}

/** Facts a decision receipt is built from. */
export interface DecisionReceiptFacts {
  request: VerifierRequestContext;
  tier: FinancialTier;
  amountUsd: string;
  /**
   * RFC 3339 UTC with 3-digit milliseconds ("2026-08-25T03:00:00.123Z") —
   * computed ONCE at the decision boundary from the gate's clock. Recorded
   * only through the instance block today (buildDecisionReceiptInput does
   * not read it); kept here so one facts object serves both builders.
   */
  decisionAt: string;
  /**
   * In-protocol pre-decision challenge nonce, when the transport has one
   * (e.g. the x402 EVC profile's 402 challenge nonce — REQUIRED there, spec
   * x402-evc-profile-v0 §4.1). The plain MPP gate has no such value.
   */
  requestNonce?: string;
  /** Present when the in-process classical path parsed the bundle. */
  bundle?: ParsedBundle;
  /** Present on deny. */
  denial?: Pick<DenyVerdict, 'code' | 'message'>;
}

/** @deprecated Renamed to {@link DecisionReceiptFacts} in 0.4.0. */
export type DecisionFacts = DecisionReceiptFacts;

/**
 * The pure instance facts of spec §3 — exactly the preimage fields, nothing
 * from the transport. A caller with no resolved tier or clock simply never
 * constructs this (no placeholder values), which is what keeps early-deny
 * receipts honestly instance-less.
 */
export interface DecisionInstanceFacts {
  /** Payee / project_key the decision bound to (§3.1.1 identifier syntax). */
  audience: string;
  /** Binding program discriminator (e.g. "mpp", "x402"). */
  program: string;
  /** Capability tokens the decision was evaluated over, order as presented. */
  capabilities: string[];
  /** Decimal USD string, exactly as decided. */
  amountUsd: string;
  /** RFC 3339 UTC, 3-digit ms. */
  decisionAt: string;
  /** Pre-decision challenge nonce, when the transport has one. */
  requestNonce?: string;
}

/**
 * Build the signed `instance` block for one gate decision
 * (spec/receipt-instance-binding-v1.md §3): the instance-shaped,
 * third-party-recomputable reference over the facts the verifier actually
 * decided on. Throws if any preimage field is outside the §3.1 domain —
 * emission MUST NOT produce a receipt a conformant verifier rejects.
 */
export function buildDecisionInstance(facts: DecisionInstanceFacts): ReceiptInstanceFields {
  const preimage: InstancePreimage = {
    audience: facts.audience,
    program: facts.program,
    capabilities: facts.capabilities,
    amountUsd: facts.amountUsd,
    decisionAt: facts.decisionAt,
    ...(facts.requestNonce !== undefined && { requestNonce: facts.requestNonce }),
  };
  return { ref: computeInstanceRef(preimage), preimage };
}

/** Derive the instance facts from resolved receipt facts (gate internal). */
export function instanceFactsFrom(facts: DecisionReceiptFacts): DecisionInstanceFacts {
  return {
    audience: facts.request.project_key,
    program: facts.request.program,
    capabilities: facts.request.granted_capabilities,
    amountUsd: facts.amountUsd,
    decisionAt: facts.decisionAt,
    ...(facts.requestNonce !== undefined && { requestNonce: facts.requestNonce }),
  };
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Hex-encode a decimal field-element string for DID formatting. */
function decToHex(dec: string): string {
  try {
    return BigInt(dec).toString(16);
  } catch {
    return 'unknown';
  }
}

/**
 * Build the CommerceReceiptInput for one gate decision. Field conventions
 * follow the gateway's decision receipts; commerce fields carry the MPP
 * context (rail/amount/merchant/intentHash).
 */
export function buildDecisionReceiptInput(facts: DecisionReceiptFacts): CommerceReceiptInput {
  const { request, bundle, denial } = facts;
  const operator = bundle?.agent.credential.operator_pubkey;
  const envelope = bundle?.agent.envelope;

  return {
    rootDid: operator ? `did:bolyra:operator:${decToHex(operator.x)}` : 'did:bolyra:anonymous',
    actingDid: request.agent_name
      ? `did:bolyra:agent:${request.agent_name}`
      : 'did:bolyra:anonymous',
    credentialCommitment: bundle?.agent.envelope.publicSignals[2] ?? '0',
    effectiveCommitment: bundle?.agent.envelope.publicSignals[2] ?? '0',
    allowed: denial === undefined,
    ...(denial !== undefined && { reasonCode: denial.code }),
    score: denial === undefined ? 1 : 0,
    permissionBitmask: bundle?.agent.credential.permission_bitmask ?? '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: envelope?.proof ?? [] },
    humanPublicSignals: [],
    agentPublicSignals: envelope?.publicSignals ?? [],
    bundleVersion: 1,
    // Distinct nonce per receipt: two decisions in the same second must not
    // collide (gateway convention for non-proof-bound receipts).
    nonce: BigInt('0x' + randomBytes(16).toString('hex')).toString(),
    commerce: {
      rail: 'mpp',
      amount: Number(facts.amountUsd),
      currency: 'USD',
      merchant: request.project_key,
      // Bare 64-hex (no 0x prefix): the @bolyra/receipts verify CLI validates
      // commerce.intentHash against /^[0-9a-fA-F]{64}$/, matching the golden
      // corpus. A 0x prefix here makes an mpp receipt fail `receipt verify`.
      intentHash: sha256Hex(
        canonicalize({
          audience: request.project_key,
          program: request.program,
          capabilities: request.granted_capabilities,
          amountUsd: facts.amountUsd,
          tier: facts.tier,
        }),
      ),
    },
  };
}

/** Throwaway probe input used only to recover the signer address. */
function probeInput(): CommerceReceiptInput {
  return {
    rootDid: 'did:bolyra:probe',
    actingDid: 'did:bolyra:probe',
    credentialCommitment: '0',
    effectiveCommitment: '0',
    allowed: false,
    reasonCode: 'probe',
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce: '0',
    commerce: { rail: 'mpp', amount: 0, currency: 'USD', merchant: 'probe', intentHash: '0'.repeat(64) },
  };
}
