/**
 * bolyra receipt verify-chain <file> — Verify a JSONL receipt log as a hash
 * chain: every ES256K signature AND the chain links (seq continuity,
 * prevReceiptHash).
 *
 * What this detects from the log alone: edited receipts (signature), deleted
 * lines, reordered lines, inserted lines, head truncation (missing genesis),
 * and a restarted chain spliced into one file. What it provably CANNOT detect
 * from the log alone: truncation from the TAIL — a chain cut after any receipt
 * is still internally consistent. Pin the head hash or receipt count
 * externally (anchoring cadence is deployment policy) and pass --expect-head /
 * --expect-count to close that gap.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { verifyReceiptChain } from '@bolyra/receipts';
import type { ChainVerifyOptions, SignedReceipt } from '@bolyra/receipts';
import { fetchAcceptedSigners } from './signer-discovery-fetch';

const HELP = `bolyra receipt verify-chain <file> — Verify a JSONL receipt log as a hash chain

Verifies every receipt signature AND the chain: seq continuity, prevReceiptHash
links, genesis sentinel. Detects edits, deleted lines, reordered lines, and
head truncation from the log alone. Tail truncation (dropping the newest
receipts) is NOT detectable without an external expectation — pin the head
hash or count from a previous run and pass it back in.

Arguments:
  <file>                 Path to a JSONL log (one signed receipt per line)

Flags:
  --signer <address>     Require every signature to recover to this address
  --signer-from <url>    Accept signers from a Receipt Signer Discovery v1
                         document (/.well-known/bolyra-signers.json).
                         Fail-closed on any fetch/schema error. With --signer
                         too, both must agree (the address must be listed)
  --expect-count <n>     Externally known receipt count (detects tail truncation)
  --expect-head <hash>   Externally known head receiptHash (detects tail truncation)
  --allow-unchained      Tolerate a PREFIX of receipts without chain fields
                         (logs that predate chaining); their signatures are
                         still verified, but deletion/reordering among them is
                         not detectable. A chain-less receipt AFTER a chained
                         one always fails (it could be an inserted line)
  --help                 Show this help
`;

export async function run(args: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      options: {
        signer: { type: 'string' },
        'signer-from': { type: 'string' },
        'expect-count': { type: 'string' },
        'expect-head': { type: 'string' },
        'allow-unchained': { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }
  const { values, positionals } = parsed;

  if (values.help) {
    console.log(HELP);
    return;
  }

  if (positionals.length === 0) {
    console.error('Error: provide a JSONL receipt log file path');
    process.exitCode = 2;
    return;
  }

  const filePath = positionals[0];
  if (!fs.existsSync(filePath)) {
    console.error(`Error: file not found: ${filePath}`);
    process.exitCode = 1;
    return;
  }

  let expectedCount: number | undefined;
  if (values['expect-count'] !== undefined) {
    // Strict: parseInt would silently accept '3abc' / '3.9' / '0x10', turning
    // a typo in the external truncation check into a wrong verdict.
    if (!/^\d+$/.test(values['expect-count'])) {
      console.error('Error: --expect-count must be a non-negative integer');
      process.exitCode = 2;
      return;
    }
    expectedCount = parseInt(values['expect-count'], 10);
  }

  // Parse the JSONL log: one signed receipt per non-empty line. Keep each
  // receipt's ORIGINAL file line number so issues point at the real line
  // even when the file contains blank lines.
  const lines = fs
    .readFileSync(filePath, 'utf-8')
    .split('\n')
    .map((line, i) => ({ line: line.trim(), lineNo: i + 1 }))
    .filter(({ line }) => line !== '');

  const receipts: SignedReceipt[] = [];
  const lineNoByReceiptIndex: number[] = [];
  for (const { line, lineNo } of lines) {
    try {
      receipts.push(JSON.parse(line) as SignedReceipt);
      lineNoByReceiptIndex.push(lineNo);
    } catch {
      console.error(`FAIL: invalid JSON at line ${lineNo}`);
      process.exitCode = 1;
      return;
    }
  }

  // Signer discovery (spec/receipt-signer-discovery-v1.md): fetch failures
  // and schema violations are verification failures, never "no restriction".
  // Checked against undefined, not truthiness: `--signer-from=` (empty value)
  // must fail closed via URL validation, not silently skip discovery.
  let accepted: Set<string> | undefined;
  if (values['signer-from'] !== undefined) {
    try {
      accepted = await fetchAcceptedSigners(values['signer-from']);
    } catch (err) {
      console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
    if (values.signer && !accepted.has(values.signer.toLowerCase())) {
      console.error(
        `FAIL: --signer and --signer-from do not agree: ${values.signer} is not listed in the discovery document`,
      );
      process.exitCode = 1;
      return;
    }
  }

  const options: ChainVerifyOptions = {
    expectedSigner: values.signer,
    expectedCount,
    expectedHeadHash: values['expect-head'],
    allowUnchained: values['allow-unchained'],
  };
  const result = verifyReceiptChain(receipts, options);

  // Discovery-only mode: verifyReceiptChain validated every signature; now
  // require each recovered signer to be listed in the discovery document.
  const discoveryFailures: string[] = [];
  if (accepted && !values.signer) {
    receipts.forEach((r, i) => {
      // Guard the receipt itself: JSON.parse accepts `null`/primitives, which
      // verifyReceiptChain reports as malformed-receipt — this pass must
      // report the same line, not crash reading .signature off null.
      const signer =
        typeof r === 'object' && r !== null ? r.signature?.signer : undefined;
      if (typeof signer !== 'string' || !accepted!.has(signer.toLowerCase())) {
        discoveryFailures.push(
          `  FAIL line ${lineNoByReceiptIndex[i]}: [signer-not-listed] signer ${signer ?? 'unknown'} is not in the discovery document`,
        );
      }
    });
  }

  console.log(
    `Checked ${result.total} receipts (${result.chained} chained, ${result.unchained} unchained)` +
      (values.signer ? ` against signer ${values.signer}` : '') +
      (accepted && !values.signer ? ` against discovery document (${accepted.size} signer(s))` : ''),
  );

  for (const issue of result.issues) {
    const where = issue.index >= 0 ? `line ${lineNoByReceiptIndex[issue.index]}: ` : '';
    console.error(`  FAIL ${where}[${issue.code}] ${issue.message}`);
  }
  for (const failure of discoveryFailures) {
    console.error(failure);
  }

  if (discoveryFailures.length > 0) {
    console.error('FAIL: receipt chain verification failed');
    process.exitCode = 1;
    return;
  }
  if (!result.ok) {
    if (result.issues.some((i) => i.code === 'missing-chain-fields')) {
      console.error(
        '  hint: pass --allow-unchained if this log STARTS with receipts ' +
          'written before chaining shipped (their signatures are still verified)',
      );
    }
    console.error('FAIL: receipt chain verification failed');
    process.exitCode = 1;
    return;
  }

  console.log('PASS: all signatures valid, chain intact');
  if (result.unchained > 0) {
    console.log(
      `  note: ${result.unchained} unchained receipt(s) predate chaining — ` +
        'deletion or reordering among them is not detectable',
    );
  }
  if (result.total === 0) {
    console.log(
      '  note: 0 receipts — an empty log is trivially consistent; deletion of ' +
        'ALL receipts is only detectable with --expect-count or --expect-head',
    );
  }
  if (result.headHash) {
    console.log(`  head: ${result.headHash} (${result.total} receipts)`);
  }
  if (expectedCount === undefined && values['expect-head'] === undefined) {
    console.log(
      '  note: truncation from the tail of the log is NOT detectable from the ' +
        'log alone — pin the head hash and count above (e.g. in your anchoring ' +
        'checkpoint) and re-verify with --expect-head / --expect-count',
    );
  }
}
