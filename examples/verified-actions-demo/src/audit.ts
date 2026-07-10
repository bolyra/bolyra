/**
 * Signed, hash-chained audit log.
 *
 * Every gateway decision — allow AND deny — becomes an ES256K-signed receipt
 * (via @bolyra/receipts) appended to audit/audit-log.jsonl, one receipt per
 * line. Receipts verify independently: anyone holding the JSONL file and the
 * signer address can check every line with @bolyra/receipts' verifyReceipt(),
 * no gateway or database required. Any edit to a receipt breaks its signature.
 *
 * Whole-log integrity comes from hash-chaining (ReceiptChain): each receipt's
 * signed payload carries { seq, prevReceiptHash }, so deleting, reordering, or
 * inserting log lines breaks verifyReceiptChain() even though every remaining
 * signature stays individually valid. Truncation from the TAIL is the one
 * thing the log alone cannot reveal — that requires anchoring the head hash /
 * receipt count externally, at a cadence the deploying enterprise configures.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  ReceiptChain,
  createAuthReceipt,
  signReceipt,
  verifyReceipt,
  verifyReceiptChain,
} from '@bolyra/receipts';
import type {
  AuthReceiptInput,
  ChainVerifyResult,
  ReceiptSignerConfig,
  SignedReceipt,
} from '@bolyra/receipts';

export interface AuditSignerInfo {
  issuer: string;
  keyId: string;
  alg: 'ES256K';
  /** Ethereum-style address recovered from the signing key. */
  signer: string;
}

export class AuditLog {
  readonly logPath: string;
  readonly signerInfo: AuditSignerInfo;
  private readonly signerConfig: ReceiptSignerConfig;
  /** Hash-chain state — one chain per log (the log is truncated per run). */
  private readonly chain = new ReceiptChain();

  constructor(dir: string) {
    fs.mkdirSync(dir, { recursive: true });
    this.logPath = path.join(dir, 'audit-log.jsonl');
    fs.writeFileSync(this.logPath, ''); // fresh log each run

    // Ephemeral demo signing key — regenerated every run. In production this
    // is the gateway operator's key (config: receipts.privateKey), and the
    // signer address below is what auditors pin as the trust anchor.
    this.signerConfig = {
      issuer: 'verified-actions-demo-gateway',
      keyId: 'demo-k1',
      privateKey: '0x' + randomBytes(32).toString('hex'),
    };

    // Derive the signer address by signing a throwaway probe payload
    // (@bolyra/receipts exposes the address via the signature envelope).
    const probe = signReceipt(
      createAuthReceipt(probeInput(), this.signerConfig),
      this.signerConfig,
    );
    this.signerInfo = {
      issuer: this.signerConfig.issuer,
      keyId: this.signerConfig.keyId,
      alg: 'ES256K',
      signer: probe.signature.signer,
    };
    fs.writeFileSync(
      path.join(dir, 'signer.json'),
      JSON.stringify(this.signerInfo, null, 2) + '\n',
    );
  }

  /** Sign one decision as the next chain link and append it to the JSONL log. */
  record(input: AuthReceiptInput): SignedReceipt {
    const payload = createAuthReceipt(input, {
      issuer: this.signerConfig.issuer,
      keyId: this.signerConfig.keyId,
    });
    const receipt = this.chain.sign(payload, this.signerConfig);
    fs.appendFileSync(this.logPath, JSON.stringify(receipt) + '\n');
    return receipt;
  }
}

/** Read all receipts from a JSONL audit log. */
export function readAuditLog(logPath: string): SignedReceipt[] {
  const raw = fs.readFileSync(logPath, 'utf8').trim();
  if (raw === '') return [];
  return raw.split('\n').map((line) => JSON.parse(line) as SignedReceipt);
}

export interface VerifiedEntry {
  receipt: SignedReceipt;
  valid: boolean;
}

/** Independently verify every receipt, optionally pinning the signer. */
export function verifyAuditLog(receipts: SignedReceipt[], expectedSigner?: string): VerifiedEntry[] {
  return receipts.map((receipt) => ({
    receipt,
    valid: verifyReceipt(receipt, expectedSigner),
  }));
}

export interface TamperResult {
  description: string;
  /** Should always be false — a tampered receipt must not verify. */
  stillVerifies: boolean;
}

/**
 * Demonstrate tamper-evidence: mutate copies of a receipt in the ways an
 * attacker would (flip the verdict, rewrite the reason, splice a signature
 * from another receipt) and confirm each mutation fails verification.
 */
export function tamperChecks(receipt: SignedReceipt, other?: SignedReceipt): TamperResult[] {
  const results: TamperResult[] = [];

  const flipped: SignedReceipt = JSON.parse(JSON.stringify(receipt));
  flipped.payload.decision.allowed = !flipped.payload.decision.allowed;
  results.push({
    description: `flip decision.allowed ${receipt.payload.decision.allowed} -> ${flipped.payload.decision.allowed}`,
    stillVerifies: verifyReceipt(flipped),
  });

  const reworded: SignedReceipt = JSON.parse(JSON.stringify(receipt));
  reworded.payload.decision.reasonCode = 'nothing to see here';
  results.push({
    description: 'rewrite decision.reasonCode',
    stillVerifies: verifyReceipt(reworded),
  });

  if (other) {
    const spliced: SignedReceipt = JSON.parse(JSON.stringify(receipt));
    spliced.signature = JSON.parse(JSON.stringify(other.signature));
    results.push({
      description: "graft another receipt's signature onto this payload",
      stillVerifies: verifyReceipt(spliced),
    });
  }

  return results;
}

/** Verify the log as a hash chain: every signature AND the links. */
export function verifyAuditChain(
  receipts: SignedReceipt[],
  expectedSigner?: string,
): ChainVerifyResult {
  return verifyReceiptChain(receipts, { expectedSigner });
}

export interface LogTamperResult {
  description: string;
  /** Should always be false — a tampered LOG must not chain-verify. */
  chainStillVerifies: boolean;
  /** Individual signatures stay valid — the reason chaining is needed at all. */
  individualSignaturesStillValid: boolean;
}

/**
 * Demonstrate whole-log tamper-evidence: delete a line and reorder two lines.
 * Both leave every remaining per-receipt signature valid — only the hash chain
 * catches them.
 */
export function logTamperChecks(receipts: SignedReceipt[]): LogTamperResult[] {
  const results: LogTamperResult[] = [];
  if (receipts.length < 3) return results;

  const deleted = [...receipts.slice(0, 1), ...receipts.slice(2)];
  results.push({
    description: `delete line 2 of ${receipts.length} (receipt ${receipts[1].id})`,
    chainStillVerifies: verifyReceiptChain(deleted).ok,
    individualSignaturesStillValid: deleted.every((r) => verifyReceipt(r)),
  });

  const reordered = [...receipts];
  [reordered[1], reordered[2]] = [reordered[2], reordered[1]];
  results.push({
    description: 'swap lines 2 and 3',
    chainStillVerifies: verifyReceiptChain(reordered).ok,
    individualSignaturesStillValid: reordered.every((r) => verifyReceipt(r)),
  });

  return results;
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
