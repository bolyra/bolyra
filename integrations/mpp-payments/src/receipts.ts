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
import { canonicalize, createCommerceReceipt, signReceipt, ReceiptChain } from '@bolyra/receipts';
import type { CommerceReceiptInput, ReceiptSignerConfig, SignedReceipt } from '@bolyra/receipts';
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
  sign(input: CommerceReceiptInput): SignedReceipt;
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
    sign(input: CommerceReceiptInput): SignedReceipt {
      return chain.sign(createCommerceReceipt(input, signerConfig), signerConfig);
    },
  };
}

/** Facts a decision receipt is built from. */
export interface DecisionFacts {
  request: VerifierRequestContext;
  tier: FinancialTier;
  amountUsd: string;
  /** Present when the in-process classical path parsed the bundle. */
  bundle?: ParsedBundle;
  /** Present on deny. */
  denial?: Pick<DenyVerdict, 'code' | 'message'>;
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
export function buildDecisionReceiptInput(facts: DecisionFacts): CommerceReceiptInput {
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
      intentHash:
        '0x' +
        sha256Hex(
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
    commerce: { rail: 'mpp', amount: 0, currency: 'USD', merchant: 'probe', intentHash: '0x0' },
  };
}
