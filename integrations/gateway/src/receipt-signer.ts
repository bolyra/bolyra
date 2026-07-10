/**
 * @bolyra/gateway — receipt signing.
 *
 * Signs an ES256K receipt (via @bolyra/receipts) for EVERY gateway decision,
 * allow and deny, in both dev and production mode. Same schema and crypto as
 * examples/verified-actions-demo: createAuthReceipt + signReceipt.
 *
 * Key resolution order:
 *   1. Explicit ReceiptSignerConfig (library option `receiptSigner`)
 *   2. config.receipts.{issuer,keyId,privateKey} from gateway.yaml
 *   3. Ephemeral key generated at startup (dev-friendly default). Receipts
 *      remain independently verifiable — verifyReceipt() recovers the signer
 *      address from the signature — but the address rotates on restart, so
 *      production deployments should pin a key via receipts.privateKey.
 */

import { randomBytes } from 'crypto';
import { createAuthReceipt, signReceipt } from '@bolyra/receipts';
import type { AuthReceiptInput, ReceiptSignerConfig, SignedReceipt } from '@bolyra/receipts';
import type { BolyraAuthContext, BolyraProofBundle } from '@bolyra/mcp';
import type { GatewayConfig, GatewayDenial } from './types';

const DEFAULT_ISSUER = 'bolyra-gateway';
const DEFAULT_KEY_ID = 'k1';

/** A resolved gateway receipt signer. */
export interface GatewayReceiptSigner {
  issuer: string;
  keyId: string;
  alg: 'ES256K';
  /** Ethereum-style address recovered from the signing key — the trust anchor auditors pin. */
  signer: string;
  /** True when the key was generated at startup rather than configured. */
  ephemeral: boolean;
  /** Sign one decision. The private key stays inside this closure. */
  sign(input: AuthReceiptInput): SignedReceipt;
}

/**
 * Resolve the gateway's receipt signer. Throws at startup if a configured
 * private key is malformed (fail fast, not on the first request).
 */
export function createGatewayReceiptSigner(
  config: GatewayConfig,
  override?: ReceiptSignerConfig,
): GatewayReceiptSigner {
  let signerConfig: ReceiptSignerConfig;
  let ephemeral = false;

  if (override) {
    signerConfig = override;
  } else if (config.receipts.privateKey) {
    signerConfig = {
      issuer: config.receipts.issuer ?? DEFAULT_ISSUER,
      keyId: config.receipts.keyId ?? DEFAULT_KEY_ID,
      privateKey: config.receipts.privateKey,
    };
  } else {
    ephemeral = true;
    signerConfig = {
      issuer: config.receipts.issuer ?? DEFAULT_ISSUER,
      keyId: config.receipts.keyId ?? DEFAULT_KEY_ID,
      privateKey: '0x' + randomBytes(32).toString('hex'),
    };
  }

  // Derive the signer address by signing a throwaway probe payload — same
  // approach as the verified-actions demo. Also validates the key material.
  const probe = signReceipt(createAuthReceipt(probeInput(), signerConfig), signerConfig);

  return {
    issuer: signerConfig.issuer,
    keyId: signerConfig.keyId,
    alg: 'ES256K',
    signer: probe.signature.signer,
    ephemeral,
    sign(input: AuthReceiptInput): SignedReceipt {
      const payload = createAuthReceipt(input, {
        issuer: signerConfig.issuer,
        keyId: signerConfig.keyId,
      });
      return signReceipt(payload, signerConfig);
    },
  };
}

/**
 * Shape guard: receipts hash the proof material, so only bundles that
 * actually carry it can back a subject-attributed receipt. Anything else is
 * treated as "no bundle" and gets an anonymous deny receipt.
 * (Same guard as the verified-actions demo's decodeBundle.)
 */
export function isReceiptableBundle(parsed: unknown): parsed is BolyraProofBundle {
  const b = parsed as BolyraProofBundle | null | undefined;
  return (
    typeof b?.credentialCommitment === 'string' &&
    typeof b?.nonce === 'string' &&
    Array.isArray(b?.humanProof?.publicSignals) &&
    Array.isArray(b?.agentProof?.publicSignals)
  );
}

/** DID for a commitment (decimal string), namespaced dev/network like @bolyra/mcp. */
function didFromCommitment(commitment: string, config: GatewayConfig): string {
  const namespace = config.devMode ? 'dev' : config.network;
  let hex: string;
  try {
    hex = BigInt(commitment).toString(16).padStart(64, '0');
  } catch {
    hex = 'unparseable';
  }
  return `did:bolyra:${namespace}:${hex}`;
}

/** DID for a bundle whose auth context is unavailable or empty. */
function didFromBundle(bundle: BolyraProofBundle, config: GatewayConfig): string {
  return didFromCommitment(bundle.credentialCommitment, config);
}

/** Receipt input for a decision made with a verified auth context. */
export function buildDecisionReceiptInput(
  bundle: BolyraProofBundle,
  authCtx: BolyraAuthContext,
  config: GatewayConfig,
  allowed: boolean,
  reasonCode: string,
): AuthReceiptInput {
  const rootDid = authCtx.did || didFromBundle(bundle, config);
  // Delegated calls act as the chain's leaf commitment, not the root — same
  // derivation @bolyra/mcp's attachReceipt uses.
  const actingDid =
    authCtx.chainDepth > 0 && authCtx.effectiveCommitment
      ? didFromCommitment(authCtx.effectiveCommitment, config)
      : rootDid;
  return {
    rootDid,
    actingDid,
    credentialCommitment: bundle.credentialCommitment,
    effectiveCommitment: authCtx.effectiveCommitment || bundle.credentialCommitment,
    allowed,
    reasonCode,
    score: authCtx.score,
    permissionBitmask: authCtx.permissionBitmask.toString(),
    chainDepth: authCtx.chainDepth,
    humanProof: bundle.humanProof,
    agentProof: bundle.agentProof,
    humanPublicSignals: bundle.humanProof.publicSignals,
    agentPublicSignals: bundle.agentProof.publicSignals,
    bundleVersion: bundle.v === 2 ? 2 : 1,
    nonce: bundle.nonce,
    delegationChain: bundle.delegationChain,
  };
}

/** Receipt input for a bundle rejected without a usable auth context. */
export function buildAuthFailReceiptInput(
  bundle: BolyraProofBundle,
  config: GatewayConfig,
  reasonCode: string,
): AuthReceiptInput {
  const did = didFromBundle(bundle, config);
  return {
    rootDid: did,
    actingDid: did,
    credentialCommitment: bundle.credentialCommitment,
    effectiveCommitment: bundle.credentialCommitment,
    allowed: false,
    reasonCode,
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: bundle.humanProof,
    agentProof: bundle.agentProof,
    humanPublicSignals: bundle.humanProof.publicSignals,
    agentPublicSignals: bundle.agentProof.publicSignals,
    bundleVersion: bundle.v === 2 ? 2 : 1,
    nonce: bundle.nonce,
    delegationChain: bundle.delegationChain,
  };
}

/**
 * Receipt input for a request with no usable proof bundle at all (missing or
 * malformed Authorization header). Even anonymous rejections leave a signed
 * record.
 */
export function buildAnonymousDenyReceiptInput(
  config: GatewayConfig,
  reasonCode: string,
): AuthReceiptInput {
  const namespace = config.devMode ? 'dev' : config.network;
  const did = `did:bolyra:${namespace}:anonymous`;
  return {
    rootDid: did,
    actingDid: did,
    credentialCommitment: '0',
    effectiveCommitment: '0',
    allowed: false,
    reasonCode,
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    // Anonymous requests carry no session nonce, so give the receipt fresh
    // entropy here: with a constant nonce, two identical anonymous denials in
    // the same second would hash to the same receipt id (and could overwrite
    // each other in file output).
    nonce: BigInt('0x' + randomBytes(16).toString('hex')).toString(),
  };
}

/** Build the receipt input for a denial recorded by the middleware. */
export function buildDenialReceiptInput(
  denial: GatewayDenial | undefined,
  config: GatewayConfig,
  toolName?: string,
): AuthReceiptInput {
  let reason = denial?.reason ?? 'denied: no reason recorded';
  // Name the attempted tool so the receipt is self-describing even when the
  // middleware-recorded reason (auth failures) predates the policy check.
  if (toolName && !reason.includes(`"${toolName}"`)) {
    reason += ` [tool: ${toolName}]`;
  }
  if (denial?.bundle && denial.authCtx) {
    return buildDecisionReceiptInput(denial.bundle, denial.authCtx, config, false, reason);
  }
  if (denial?.bundle) {
    return buildAuthFailReceiptInput(denial.bundle, config, reason);
  }
  return buildAnonymousDenyReceiptInput(config, reason);
}

/** Minimal input used once at startup to derive the signer address. */
function probeInput(): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:dev:probe',
    actingDid: 'did:bolyra:dev:probe',
    credentialCommitment: '0',
    effectiveCommitment: '0',
    allowed: false,
    reasonCode: 'signer-probe',
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce: '0',
  };
}
