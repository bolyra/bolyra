/**
 * npm run report -- --bundle <dir> --signer <0xaddr> [--expect-count n] [--expect-head 0x…] [--out dir]
 *
 * Reads a trial bundle, classifies it against reviewer-supplied anchors, and
 * writes report.html + report.json. Exit 0 when a report was written, whatever
 * the findings say; exit 2 on rejected flags or unreadable input. The bundle
 * directory is never written to.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { BundleInputError, classify } from './classify';
import type { Anchors, BundleFiles } from './classify';
import { render } from './render';

const USAGE = `Usage: npm run report -- --bundle <dir> --signer <0xaddress> [--expect-count <n>] [--expect-head <0xhash>] [--out <dir>]

  --bundle        a trial bundle directory (receipts.jsonl and summary.json required)
  --signer        the address every receipt signature must recover to (reviewer-supplied)
  --expect-count  externally known receipt count (closes tail-truncation by count)
  --expect-head   externally known head receiptHash (closes tail-truncation by head)
  --out           output directory; default ./report-out/<bundle name>/; must not be inside the bundle

Anchors are taken from these flags only; signer.json and summary.json are compared against them, never used as anchors.
`;

export function main(argv: string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        bundle: { type: 'string' },
        signer: { type: 'string' },
        'expect-count': { type: 'string' },
        'expect-head': { type: 'string' },
        out: { type: 'string' },
        help: { type: 'boolean', default: false },
      },
      allowPositionals: false,
    });
  } catch (err) {
    return usage((err as Error).message);
  }
  const v = parsed.values;
  if (v.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (!v.bundle) return usage('--bundle is required');
  if (!v.signer) return usage('--signer is required');
  if (!/^0x[0-9a-fA-F]{40}$/.test(v.signer)) return usage('--signer must be a 0x-prefixed 20-byte hex address');
  const anchors: Anchors = { signer: v.signer };
  if (v['expect-count'] !== undefined) {
    if (!/^\d+$/.test(v['expect-count'])) return usage('--expect-count must be a non-negative integer');
    anchors.expectCount = Number(v['expect-count']);
  }
  if (v['expect-head'] !== undefined) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(v['expect-head'])) return usage('--expect-head must be a 0x-prefixed 32-byte hex hash');
    anchors.expectHead = v['expect-head'];
  }

  const bundleDir = path.resolve(v.bundle);
  const outDir = path.resolve(v.out ?? path.join('report-out', path.basename(bundleDir)));
  const rel = path.relative(bundleDir, outDir);
  if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
    return usage(`--out must not be inside the bundle directory (${bundleDir})`);
  }

  let files: BundleFiles;
  try {
    files = {
      receiptsJsonl: fs.readFileSync(path.join(bundleDir, 'receipts.jsonl'), 'utf8'),
      summaryJson: fs.readFileSync(path.join(bundleDir, 'summary.json'), 'utf8'),
      signerJson: readOptional(path.join(bundleDir, 'signer.json')),
      verifyTxt: readOptional(path.join(bundleDir, 'VERIFY.txt')),
    };
  } catch (err) {
    return usage(`cannot read bundle: ${(err as Error).message}`);
  }

  let report;
  try {
    report = classify(files, anchors, { bundleName: path.basename(bundleDir) });
  } catch (err) {
    if (err instanceof BundleInputError) return usage(err.message);
    throw err;
  }
  const html = render(report, { receiptsPath: './receipts.jsonl' });

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(outDir, 'report.html'), html);

  const counts: Record<string, number> = { SIGNED: 0, OBSERVED: 0, DERIVED: 0, ABSENT: 0, FAILED: 0 };
  for (const f of report.findings) counts[f.status] = (counts[f.status] ?? 0) + 1;
  process.stdout.write(
    `report written: ${path.join(outDir, 'report.html')} (and report.json)\n` +
      `findings: ${Object.entries(counts).map(([k, n]) => `${k}: ${n}`).join('  ')}\n` +
      `anchors came from the command line; see the report's Anchors section for what that does and does not establish.\n`,
  );
  return 0;
}

function readOptional(p: string): string | undefined {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return undefined;
  }
}

function usage(problem: string): number {
  process.stderr.write(`error: ${problem}\n\n${USAGE}`);
  return 2;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
