/**
 * Optional signed receipts for hosted verify decisions.
 *
 * Reuses `@bolyra/receipts` (ES256K over canonical JSON — pure `@noble` crypto,
 * workerd-safe) with the same `createAuthReceipt` construction as
 * `@bolyra/gateway`. Signing is enabled by the `RECEIPT_SIGNER_KEY` Worker
 * secret; when unset, responses simply carry no receipt.
 *
 * TRANSPORT: the response body is the STRICT spec §3.4 verdict object (closed
 * schema — a receipt field inside it would be schema-invalid), so the signed
 * receipt travels in the `X-Bolyra-Receipt` response header, base64url-encoded.
 *
 * Receipt failures never affect the verdict: best-effort, log-and-omit.
 */

import { createAuthReceipt, signReceipt } from '@bolyra/receipts';
import type { AuthReceiptInput } from '@bolyra/receipts';
import { parseBundle, type ParsedBundle } from './verify/bundle';
import { recomputeCredentialCommitment } from './verify/scope';
import type { Verdict } from './verify/verdict';

export interface ReceiptEnv {
  RECEIPT_SIGNER_KEY?: string;
  RECEIPT_ISSUER?: string;
  RECEIPT_KEY_ID?: string;
}

function didFromCommitment(commitment: string): string {
  let hex: string;
  try {
    hex = BigInt(commitment).toString(16).padStart(64, '0');
  } catch {
    hex = 'unparseable';
  }
  return `did:bolyra:preview:${hex}`;
}

function randomDecimalNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt('0x' + hex).toString();
}

/** Best-effort re-parse of the request bundle for receipt attribution. */
function tryParseBundle(body: unknown): ParsedBundle | undefined {
  if (typeof body !== 'object' || body === null) return undefined;
  const bundle = (body as { bundle?: unknown }).bundle;
  if (typeof bundle !== 'string' || bundle.length === 0) return undefined;
  try {
    return parseBundle(bundle);
  } catch {
    return undefined;
  }
}

function buildInput(verdict: Verdict, body: unknown): AuthReceiptInput {
  const allowed = verdict.verdict === 'allow';
  const reasonCode = verdict.verdict === 'allow' ? 'allow' : verdict.code;
  const bundle = tryParseBundle(body);

  if (bundle === undefined) {
    const did = 'did:bolyra:preview:anonymous';
    return {
      rootDid: did,
      actingDid: did,
      credentialCommitment: '0',
      effectiveCommitment: '0',
      allowed,
      reasonCode,
      score: allowed ? 1 : 0,
      permissionBitmask: '0',
      chainDepth: 0,
      humanProof: { proof: [] },
      agentProof: { proof: [] },
      humanPublicSignals: [],
      agentPublicSignals: [],
      bundleVersion: 1,
      nonce: randomDecimalNonce(),
    };
  }

  const cred = bundle.agent.credential;
  let credentialCommitment = '0';
  try {
    credentialCommitment = recomputeCredentialCommitment({
      modelHash: BigInt(cred.model_hash),
      opX: BigInt(cred.operator_pubkey.x),
      opY: BigInt(cred.operator_pubkey.y),
      bitmask: BigInt(cred.permission_bitmask),
      expiry: BigInt(cred.expiry),
    }).toString();
  } catch {
    // Ill-formed field elements: fall through with '0' — the receipt still
    // records the decision.
  }
  const did = didFromCommitment(credentialCommitment);
  const nullifier = bundle.agent.envelope.publicSignals[1];

  return {
    rootDid: did,
    actingDid: did,
    credentialCommitment,
    effectiveCommitment: credentialCommitment,
    allowed,
    reasonCode,
    score: allowed ? 1 : 0,
    permissionBitmask: cred.permission_bitmask,
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: bundle.agent.envelope.proof },
    humanPublicSignals: [],
    agentPublicSignals: bundle.agent.envelope.publicSignals,
    bundleVersion: 1,
    nonce: nullifier !== undefined && nullifier !== '0' ? nullifier : randomDecimalNonce(),
  };
}

/**
 * Sign a receipt for a decision and return it base64url-encoded for the
 * `X-Bolyra-Receipt` header, or undefined when signing is disabled or fails.
 */
export function buildReceiptHeader(
  verdict: Verdict,
  body: unknown,
  env: ReceiptEnv,
): string | undefined {
  const privateKey = env.RECEIPT_SIGNER_KEY;
  if (privateKey === undefined || privateKey === '') return undefined;
  try {
    const config = {
      issuer: env.RECEIPT_ISSUER ?? 'bolyra-hosted-verify-preview',
      keyId: env.RECEIPT_KEY_ID ?? 'preview-1',
      privateKey,
    };
    const payload = createAuthReceipt(buildInput(verdict, body), config);
    const signed = signReceipt(payload, config);
    const json = JSON.stringify(signed);
    const bytes = new TextEncoder().encode(json);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (e) {
    console.error('hosted-verify receipt signing failed:', e instanceof Error ? e.message : e);
    return undefined;
  }
}
