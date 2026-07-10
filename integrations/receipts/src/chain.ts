/**
 * Receipt hash-chaining — whole-log integrity on top of per-receipt signatures.
 *
 * Individual receipts are ES256K-signed and tamper-evident on their own; a log
 * of receipts is not — deleting or reordering whole lines leaves every
 * remaining signature valid. Chaining closes that gap:
 *
 * - Each chained receipt carries `payload.chain = { seq, prevReceiptHash }`.
 *   These fields live INSIDE the signed payload, so they cannot be rewritten
 *   after the fact without breaking the signature.
 * - `seq` is 0-based and monotonic per log (per writer process).
 * - `prevReceiptHash` is the previous receipt's canonical hash; the first
 *   receipt in a log uses the documented sentinel GENESIS_PREV_RECEIPT_HASH
 *   (32 zero bytes, hex).
 * - `receiptHash` is attached to the signed-receipt ENVELOPE as a convenience:
 *   keccak256 over canonicalize({ payload, signature }) — it commits to both
 *   the payload and the exact signature bytes, and excludes `id` and the
 *   `receiptHash` field itself. Verifiers never trust it: verifyReceiptChain
 *   recomputes it and only flags a stored value that disagrees.
 *
 * Backward compatibility: all fields are additive. Chain-less receipts keep
 * signing and verifying exactly as before, chained receipts verify with the
 * existing per-receipt verifyReceipt(), and chain verification is a separate
 * step (verifyReceiptChain).
 *
 * What chain verification can and cannot detect (be precise with auditors):
 * - DETECTABLE from the log alone: edits to any receipt (signature), deleted
 *   lines (prev-hash/seq break), reordered lines, inserted lines, head
 *   truncation (log no longer starts at genesis), a restarted chain spliced
 *   into the same file.
 * - NOT detectable from the log alone: truncation from the TAIL — a chain cut
 *   after any receipt is still internally consistent. Detecting it requires
 *   external knowledge: the expected receipt count (expectedCount) or the
 *   expected head hash (expectedHeadHash), e.g. from a periodically anchored
 *   checkpoint. Anchoring/checkpoint cadence is deployment policy
 *   (enterprise-configurable), not part of this library.
 */

import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical';
import { signReceipt, verifyReceipt } from './sign';
import type { ReceiptPayload, ReceiptSignerConfig, SignedReceipt } from './types';

/** Sentinel prevReceiptHash for the first receipt in a log: 32 zero bytes. */
export const GENESIS_PREV_RECEIPT_HASH = '0x' + '0'.repeat(64);

/**
 * Canonical hash of a signed receipt: keccak256 over
 * canonicalize({ payload, signature }). Excludes `id` (derivable from
 * signature.payloadHash) and `receiptHash` itself (to avoid self-reference).
 */
export function computeReceiptHash(receipt: SignedReceipt): string {
  const canonical = canonicalize({ payload: receipt.payload, signature: receipt.signature });
  return '0x' + bytesToHex(keccak_256(new TextEncoder().encode(canonical)));
}

/**
 * Stateful writer-side chain: assigns { seq, prevReceiptHash } to each payload
 * before signing and attaches the resulting receiptHash to the envelope.
 *
 * One ReceiptChain per log. State lives with the writer process; a restart
 * starts a new chain (seq 0, genesis sentinel) — write it to a new log file
 * if the log must verify as a single chain.
 *
 * State advances when a receipt is SIGNED, not when it is durably written.
 * This is deliberate: if a signed receipt is subsequently lost (a dropped
 * write), the next receipt links across the gap and chain verification FAILS
 * — which is the truthful outcome, because the log really is incomplete. A
 * writer-acknowledged design (advance only after persistence) would instead
 * make the surviving log verify clean and silently hide the loss.
 */
export class ReceiptChain {
  private seq = 0;
  private prevReceiptHash = GENESIS_PREV_RECEIPT_HASH;

  /** Sign one payload as the next link. Advances state only on success. */
  sign(payload: ReceiptPayload, config: ReceiptSignerConfig): SignedReceipt {
    const chained: ReceiptPayload = {
      ...payload,
      chain: { seq: this.seq, prevReceiptHash: this.prevReceiptHash },
    };
    const receipt = signReceipt(chained, config);
    const receiptHash = computeReceiptHash(receipt);
    this.seq += 1;
    this.prevReceiptHash = receiptHash;
    return { ...receipt, receiptHash };
  }
}

export type ReceiptChainIssueCode =
  | 'malformed-receipt'
  | 'signature-invalid'
  | 'missing-chain-fields'
  | 'unchained-after-chained'
  | 'genesis-mismatch'
  | 'chain-restart'
  | 'seq-mismatch'
  | 'prev-hash-mismatch'
  | 'receipt-hash-mismatch'
  | 'count-mismatch'
  | 'head-hash-mismatch';

export interface ReceiptChainIssue {
  /** 0-based position in the log; -1 for log-level issues (count/head checks). */
  index: number;
  receiptId?: string;
  code: ReceiptChainIssueCode;
  message: string;
}

export interface ChainVerifyOptions {
  /** Require every signature to recover to this address. */
  expectedSigner?: string;
  /**
   * Externally known receipt count. Without it, truncation from the TAIL of
   * the log is NOT detectable — a cut chain is still internally consistent.
   */
  expectedCount?: number;
  /** Externally known (anchored) hash of the last receipt — same purpose. */
  expectedHeadHash?: string;
  /**
   * Tolerate a PREFIX of receipts without chain fields (logs that predate
   * chaining). Their signatures are still verified, but deletion/reordering
   * among them is NOT detectable. Only the prefix is tolerated: a chain-less
   * receipt appearing AFTER any chained receipt is always an issue
   * ('unchained-after-chained') — otherwise any validly signed chain-less
   * receipt could be spliced into or appended to a chained log undetected.
   */
  allowUnchained?: boolean;
}

export interface ChainVerifyResult {
  ok: boolean;
  total: number;
  chained: number;
  unchained: number;
  issues: ReceiptChainIssue[];
  /**
   * Recomputed hash of the last chained receipt — pin/anchor this externally
   * to make tail truncation detectable on the next verification.
   */
  headHash?: string;
}

/**
 * Verify a receipt log as a hash chain: every signature AND the chain links.
 * Receipts must be passed in log order.
 */
export function verifyReceiptChain(
  receipts: SignedReceipt[],
  options: ChainVerifyOptions = {},
): ChainVerifyResult {
  const issues: ReceiptChainIssue[] = [];
  let chained = 0;
  let unchained = 0;
  let prev: { seq: number; hash: string } | undefined;
  let headHash: string | undefined;

  receipts.forEach((receipt, index) => {
    // 0. Shape guard: collected logs can contain non-receipt entries (e.g.
    // the gateway's tagged `unsigned: true` raw fallback records). Flag them
    // as malformed instead of throwing on property access below.
    if (
      receipt === null ||
      typeof receipt !== 'object' ||
      typeof receipt.payload !== 'object' ||
      receipt.payload === null ||
      typeof receipt.signature !== 'object' ||
      receipt.signature === null
    ) {
      issues.push({
        index,
        code: 'malformed-receipt',
        message: `entry #${index} is not a signed receipt (missing payload/signature) — a foreign or corrupted log line`,
      });
      return;
    }

    const id = receipt.id;

    // 1. Per-receipt signature (chain fields, when present, are signed).
    if (!verifyReceipt(receipt, options.expectedSigner)) {
      issues.push({
        index,
        receiptId: id,
        code: 'signature-invalid',
        message: `receipt ${id ?? `#${index}`} failed ES256K signature verification${options.expectedSigner ? ` against signer ${options.expectedSigner}` : ''}`,
      });
    }

    // 2. Chain fields present?
    const chain = receipt.payload.chain;
    if (!chain) {
      unchained += 1;
      if (prev !== undefined) {
        // Never tolerated, even with allowUnchained: after the first chained
        // receipt every line must chain, or any validly signed chain-less
        // receipt could be inserted/appended without detection.
        issues.push({
          index,
          receiptId: id,
          code: 'unchained-after-chained',
          message: `receipt ${id ?? `#${index}`} has no chain fields but follows chained receipts — an inserted or appended line (pre-chaining receipts can only form a prefix)`,
        });
      } else if (!options.allowUnchained) {
        issues.push({
          index,
          receiptId: id,
          code: 'missing-chain-fields',
          message: `receipt ${id ?? `#${index}`} has no chain fields — deletion or reordering around it is undetectable (re-run with allowUnchained to tolerate a pre-chaining prefix)`,
        });
      }
      return;
    }
    chained += 1;

    // 3. Link check against the previous CHAINED receipt.
    const actualHash = computeReceiptHash(receipt);
    if (prev === undefined) {
      if (chain.seq !== 0 || chain.prevReceiptHash !== GENESIS_PREV_RECEIPT_HASH) {
        issues.push({
          index,
          receiptId: id,
          code: 'genesis-mismatch',
          message: `first chained receipt has seq ${chain.seq} and prevReceiptHash ${chain.prevReceiptHash} — expected seq 0 with the genesis sentinel; receipts before it were likely deleted (head truncation)`,
        });
      }
    } else if (chain.seq === 0 && chain.prevReceiptHash === GENESIS_PREV_RECEIPT_HASH) {
      issues.push({
        index,
        receiptId: id,
        code: 'chain-restart',
        message: `receipt ${id ?? `#${index}`} starts a new chain (seq 0, genesis sentinel) mid-log — writer restart or spliced logs; verify each chain from its own log file`,
      });
    } else {
      if (chain.seq !== prev.seq + 1) {
        issues.push({
          index,
          receiptId: id,
          code: 'seq-mismatch',
          message: `receipt ${id ?? `#${index}`} has seq ${chain.seq}, expected ${prev.seq + 1} — receipts were deleted, reordered, or skipped`,
        });
      }
      if (chain.prevReceiptHash !== prev.hash) {
        issues.push({
          index,
          receiptId: id,
          code: 'prev-hash-mismatch',
          message: `receipt ${id ?? `#${index}`} prevReceiptHash does not match the preceding receipt's hash — the log was altered between them (deleted, reordered, or inserted lines)`,
        });
      }
    }

    // 4. Stored convenience hash, if present, must agree with the recomputed one.
    if (receipt.receiptHash !== undefined && receipt.receiptHash !== actualHash) {
      issues.push({
        index,
        receiptId: id,
        code: 'receipt-hash-mismatch',
        message: `receipt ${id ?? `#${index}`} carries receiptHash ${receipt.receiptHash}, but its content hashes to ${actualHash}`,
      });
    }

    prev = { seq: chain.seq, hash: actualHash };
    headHash = actualHash;
  });

  // 5. External expectations — the only way to detect tail truncation.
  if (options.expectedCount !== undefined && receipts.length !== options.expectedCount) {
    issues.push({
      index: -1,
      code: 'count-mismatch',
      message: `log holds ${receipts.length} receipts, expected ${options.expectedCount}${receipts.length < options.expectedCount ? ' — consistent with tail truncation' : ''}`,
    });
  }
  if (options.expectedHeadHash !== undefined && headHash !== options.expectedHeadHash) {
    issues.push({
      index: -1,
      code: 'head-hash-mismatch',
      message: `last chained receipt hashes to ${headHash ?? '(none)'}, expected head ${options.expectedHeadHash} — consistent with tail truncation or a diverged log`,
    });
  }

  return {
    ok: issues.length === 0,
    total: receipts.length,
    chained,
    unchained,
    issues,
    headHash,
  };
}
