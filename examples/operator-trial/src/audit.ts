/**
 * Receipts and the result bundle (spec §3.3).
 *
 * Signing goes through @bolyra/gateway's createGatewayReceiptSigner: an
 * ephemeral ES256K key, hash-chained via ReceiptChain. This module owns the
 * file. ReceiptChain.sign advances its state BEFORE the append, so a signed
 * receipt that fails to persist would leave a gap every later receipt chains
 * past. On the first append failure the file is rolled back to the last
 * committed byte and no further receipts are signed; the file then holds an
 * intact prefix, and that prefix is all the bundle describes.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createGatewayReceiptSigner } from '@bolyra/gateway';
import type { GatewayConfig, GatewayReceiptSigner } from '@bolyra/gateway';
import { verifyReceiptChain } from '@bolyra/receipts';
import type { AuthReceiptInput, SignedReceipt } from '@bolyra/receipts';
import { CLI_VERSION, PACKAGES, TRIAL_VERSION } from './versions';

export type FileState = 'ok' | 'broken' | 'unverifiable';

export class AuditWriteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditWriteError';
  }
}

/** Injectable file operations, for the write-failure tests. */
export interface AuditIo {
  appendFileSync(filePath: string, data: string): void;
  truncateSync(filePath: string, length: number): void;
  /** Used for every artifact write (signer.json, summary.json, VERIFY.txt). */
  writeFileSync(filePath: string, data: string): void;
}

export interface AuditOptions {
  runDir: string;
  gatewayConfig: GatewayConfig;
  io?: Partial<AuditIo>;
}

export interface SignerInfo {
  issuer: string;
  keyId: string;
  alg: 'ES256K';
  signer: string;
  ephemeral: true;
}

/** One attempt as recorded in summary.json. Mirrors host.ts's shape plus n/credential. */
export interface SummaryAttempt {
  n: number;
  credential: string;
  decision: 'allow' | 'deny';
  stage?: string;
  reason: string;
  httpStatus: number;
  dispatched: boolean;
  upstreamStatus: number | null;
  outcome: string;
  receiptId: string | null;
  receiptError?: string;
}

export interface FinalizeInput {
  attemptsOk: boolean;
  attempts: SummaryAttempt[];
  dispatchCounts: [number, number, number];
  dryRun: boolean;
  action: { name: string; method: string; host: string; path: string };
  startedAt: string;
  finishedAt: string;
  /** Values that must not appear anywhere in the bundle. */
  secrets: string[];
}

export interface FinalizeResult {
  ok: boolean;
  reason?: string;
  receiptCount: number | null;
  headReceiptHash: string | null;
  verifyCommand: string | null;
}

export class Audit {
  readonly runDir: string;
  readonly receiptsPath: string;
  readonly signerInfo: SignerInfo;
  fileState: FileState = 'ok';
  private committedBytes = 0;
  private readonly signer: GatewayReceiptSigner;
  private readonly io: AuditIo;

  constructor(opts: AuditOptions) {
    this.runDir = opts.runDir;
    this.receiptsPath = path.join(opts.runDir, 'receipts.jsonl');
    this.io = {
      appendFileSync: opts.io?.appendFileSync ?? ((p, d) => fs.appendFileSync(p, d)),
      truncateSync: opts.io?.truncateSync ?? ((p, l) => fs.truncateSync(p, l)),
      writeFileSync: opts.io?.writeFileSync ?? ((p, d) => fs.writeFileSync(p, d)),
    };

    // Everything below that can throw happens BEFORE the directory exists,
    // so a failure here leaves nothing behind.
    this.signer = createGatewayReceiptSigner(opts.gatewayConfig);
    if (!this.signer.ephemeral) {
      throw new Error('trial signer must be ephemeral; do not configure receipts.privateKey');
    }
    this.signerInfo = {
      issuer: this.signer.issuer,
      keyId: this.signer.keyId,
      alg: 'ES256K',
      signer: this.signer.signer,
      ephemeral: true,
    };

    // Reserve the run directory atomically: a non-recursive mkdir fails with
    // EEXIST if anything else created it first, so two runs can never share
    // (and later delete) the same directory.
    fs.mkdirSync(path.dirname(opts.runDir), { recursive: true });
    try {
      fs.mkdirSync(opts.runDir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new Error(`run directory already exists: ${opts.runDir}`);
      }
      throw err;
    }

    // From here the directory is ours. If an initial write fails, remove it
    // before rethrowing so no caller has to clean up an instance that was
    // never constructed.
    try {
      this.io.writeFileSync(path.join(opts.runDir, 'signer.json'), JSON.stringify(this.signerInfo, null, 2) + '\n');
      this.io.writeFileSync(this.receiptsPath, '');
    } catch (err) {
      fs.rmSync(opts.runDir, { recursive: true, force: true });
      throw err;
    }
  }

  /** Sign and persist one decision. Throws AuditWriteError after rolling back a failed append. */
  record(input: AuthReceiptInput): SignedReceipt {
    if (this.fileState !== 'ok') {
      throw new AuditWriteError('chain broken by earlier write failure');
    }
    const receipt = this.signer.sign(input);
    const line = JSON.stringify(receipt) + '\n';
    try {
      this.io.appendFileSync(this.receiptsPath, line);
    } catch (err) {
      this.fileState = 'broken';
      try {
        this.io.truncateSync(this.receiptsPath, this.committedBytes);
      } catch {
        this.fileState = 'unverifiable';
      }
      throw new AuditWriteError(`receipt write failed: ${(err as Error).message}`);
    }
    this.committedBytes = fs.statSync(this.receiptsPath).size;
    return receipt;
  }

  readReceipts(): SignedReceipt[] {
    const raw = fs.readFileSync(this.receiptsPath, 'utf8').trim();
    if (raw === '') return [];
    return raw.split('\n').map((l) => JSON.parse(l) as SignedReceipt);
  }

  /**
   * The last receipt as it exists ON DISK (the host verifies this, not the
   * in-memory object, before dispatching). Null when the file is empty or the
   * last line does not parse.
   */
  readBackLast(): SignedReceipt | null {
    const raw = fs.readFileSync(this.receiptsPath, 'utf8').trimEnd();
    if (raw === '') return null;
    const last = raw.slice(raw.lastIndexOf('\n') + 1);
    try {
      return JSON.parse(last) as SignedReceipt;
    } catch {
      return null;
    }
  }

  /**
   * Cleanup for a run that ended by exception before finalize. Scans what was
   * written; deletes the directory on a hit or if the scan itself fails, so a
   * retained directory is always a scanned one. Only ever deletes the
   * directory this instance created.
   */
  abort(secrets: string[]): void {
    let hit: string | null;
    try {
      hit = this.scanSecrets(secrets);
    } catch {
      hit = 'scan failed';
    }
    if (hit) fs.rmSync(this.runDir, { recursive: true, force: true });
  }

  finalize(input: FinalizeInput): FinalizeResult {
    try {
      return this.finalizeInner(input);
    } catch (err) {
      // A summary/VERIFY write failure must not leave an unscanned directory.
      const hit = this.scanSecretsOrFail(input.secrets);
      if (hit) return this.deleteAndFail(hit);
      return { ok: false, reason: `finalize failed: ${(err as Error).message}`, receiptCount: null, headReceiptHash: null, verifyCommand: null };
    }
  }

  private finalizeInner(input: FinalizeInput): FinalizeResult {
    // Step 0: scan whatever exists before anything else is decided, so a kept
    // directory is never an unscanned directory.
    const early = this.scanSecretsOrFail(input.secrets);
    if (early) return this.deleteAndFail(early);

    const base = {
      trialVersion: TRIAL_VERSION,
      packages: PACKAGES,
      dryRun: input.dryRun,
      action: input.action,
      attempts: input.attempts,
      dispatchCounts: input.dispatchCounts,
      startedAt: input.startedAt,
      finishedAt: input.finishedAt,
      fileState: this.fileState,
      note: 'unsigned observations; signer key is ephemeral',
    };

    if (this.fileState === 'unverifiable') {
      this.writeSummary({ ...base, ok: false, receiptCount: null, headReceiptHash: null });
      return this.scanAfter(input.secrets, { ok: false, reason: 'receipt file unverifiable', receiptCount: null, headReceiptHash: null, verifyCommand: null });
    }

    const receipts = this.readReceipts();
    if (receipts.length === 0) {
      this.writeSummary({ ...base, ok: false, receiptCount: 0, headReceiptHash: null });
      return this.scanAfter(input.secrets, { ok: false, reason: 'no receipts were written', receiptCount: 0, headReceiptHash: null, verifyCommand: null });
    }

    const chain = verifyReceiptChain(receipts, {
      expectedSigner: this.signerInfo.signer,
      expectedCount: receipts.length,
    });
    if (!chain.ok || !chain.headHash) {
      const issues = chain.issues.map((i) => i.code).join(', ');
      return this.scanAfter(input.secrets, { ok: false, reason: `receipt chain failed verification: ${issues}`, receiptCount: receipts.length, headReceiptHash: null, verifyCommand: null });
    }

    const ok = input.attemptsOk && this.fileState === 'ok';
    const verifyCommand =
      `npx @bolyra/cli@${CLI_VERSION} receipt verify-chain ./receipts.jsonl ` +
      `--signer ${this.signerInfo.signer} --expect-count ${receipts.length} --expect-head ${chain.headHash}`;

    // Order matters: VERIFY.txt first, the summary last and atomically, so a
    // retained directory never holds a summary saying ok:true next to a
    // missing or partial VERIFY.txt. On any write failure remove the partial
    // artifacts, persist ok:false if we can, and let the outer catch scan.
    try {
      this.io.writeFileSync(path.join(this.runDir, 'VERIFY.txt'), verifyCommand + '\n');
      this.writeSummary({ ...base, ok, receiptCount: receipts.length, headReceiptHash: chain.headHash });
    } catch (err) {
      fs.rmSync(path.join(this.runDir, 'VERIFY.txt'), { force: true });
      fs.rmSync(path.join(this.runDir, 'summary.json'), { force: true });
      fs.rmSync(path.join(this.runDir, 'summary.json.tmp'), { force: true });
      try {
        this.writeSummary({ ...base, ok: false, receiptCount: receipts.length, headReceiptHash: chain.headHash, finalizeError: (err as Error).message });
      } catch {
        // No summary at all is acceptable; a wrong one is not.
      }
      throw err;
    }

    return this.scanAfter(input.secrets, { ok, receiptCount: receipts.length, headReceiptHash: chain.headHash, verifyCommand });
  }

  /**
   * Atomic publish: write to a temp file, then rename over summary.json. The
   * temp file never survives, whether the write or the rename fails.
   */
  private writeSummary(summary: Record<string, unknown>): void {
    const target = path.join(this.runDir, 'summary.json');
    const tmp = target + '.tmp';
    try {
      this.io.writeFileSync(tmp, JSON.stringify(summary, null, 2) + '\n');
      fs.renameSync(tmp, target);
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  }

  /** Returns "<file>" naming the first file containing a secret, or null. */
  private scanSecrets(secrets: string[]): string | null {
    if (secrets.length === 0 || !fs.existsSync(this.runDir)) return null;
    for (const name of fs.readdirSync(this.runDir)) {
      const content = fs.readFileSync(path.join(this.runDir, name), 'utf8');
      for (const s of secrets) {
        if (content.includes(s)) return name;
      }
    }
    return null;
  }

  /** Like scanSecrets, but a scan that cannot complete counts as a hit. */
  private scanSecretsOrFail(secrets: string[]): string | null {
    try {
      return this.scanSecrets(secrets);
    } catch {
      return 'scan failed';
    }
  }

  private scanAfter(secrets: string[], result: FinalizeResult): FinalizeResult {
    const hit = this.scanSecretsOrFail(secrets);
    return hit ? this.deleteAndFail(hit) : result;
  }

  private deleteAndFail(file: string): FinalizeResult {
    fs.rmSync(this.runDir, { recursive: true, force: true });
    return {
      ok: false,
      reason: `a resolved secret value was found in ${file}; the run directory was deleted`,
      receiptCount: null,
      headReceiptHash: null,
      verifyCommand: null,
    };
  }
}
