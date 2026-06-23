/**
 * bolyra replay — re-evaluate receipts against current or alternate policy.
 *
 * Makes receipts executable developer artifacts. Shows what happened,
 * what would happen now, and the diff between the two.
 *
 * Usage:
 *   bolyra replay last
 *   bolyra replay <receipt-file>
 *   bolyra replay last --with-policy shield.yaml
 *   bolyra replay last --diff
 *   bolyra replay --receipt-dir ./receipts last
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseArgs } from 'node:util';

const HELP = `
bolyra replay — re-evaluate receipts against current or alternate policy

Usage:
  bolyra replay last [options]
  bolyra replay <receipt-file> [options]
  bolyra replay all [options]

Options:
  --with-policy <path>   Re-evaluate against this policy file (default: no policy = allow all)
  --diff                 Show diff between original and replayed decisions
  --receipt-dir <path>   Directory containing receipt NDJSON files (default: current dir)
  --format <fmt>         Output format: table (default), json, ndjson
  --redact               Redact DIDs and timestamps for sharing
  --help                 Show this help

Examples:
  bolyra replay last
  bolyra replay last --with-policy shield.yaml --diff
  bolyra replay ./receipts.ndjson --with-policy shield.yaml
  bolyra replay all --with-policy shield.yaml --diff
  bolyra replay last --redact > share-with-team.txt
`.trim();

interface Receipt {
  decision: 'allow' | 'deny';
  toolName?: string;
  did?: string;
  score?: number;
  reason?: string;
  timestamp?: string;
  permissionBitmask?: string;
}

interface PolicyEntry {
  requireBitmask: number;
  minScore?: number;
  maxChainDepth?: number;
}

interface ReplayResult {
  original: Receipt;
  replayed: {
    decision: 'allow' | 'deny';
    reason?: string;
  };
  changed: boolean;
}

export async function run(argv: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        'with-policy': { type: 'string' },
        diff: { type: 'boolean', default: false },
        'receipt-dir': { type: 'string', default: '.' },
        format: { type: 'string', default: 'table' },
        redact: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  if (parsed.values.help) {
    console.log(HELP);
    process.exit(0);
  }

  const target = parsed.positionals[0];
  if (!target) {
    console.error('Error: specify "last", "all", or a receipt file path');
    console.log(HELP);
    process.exit(1);
  }

  const policyPath = parsed.values['with-policy'] as string | undefined;
  const showDiff = parsed.values.diff as boolean;
  const receiptDir = parsed.values['receipt-dir'] as string;
  const format = parsed.values.format as string;
  const redact = parsed.values.redact as boolean;

  // Load policy if provided
  const policy = policyPath ? loadPolicy(policyPath) : new Map<string, PolicyEntry>();

  // Load receipts
  const receipts = loadReceipts(target, receiptDir);

  if (receipts.length === 0) {
    console.error('No receipts found.');
    process.exit(1);
  }

  // Replay each receipt against the policy
  const results: ReplayResult[] = receipts.map(r => replayReceipt(r, policy));

  // Output
  if (format === 'json') {
    const output = redact ? results.map(redactResult) : results;
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  if (format === 'ndjson') {
    for (const r of results) {
      const output = redact ? redactResult(r) : r;
      console.log(JSON.stringify(output));
    }
    return;
  }

  // Table format (default)
  printReplayTable(results, showDiff, redact, policyPath);
}

function loadPolicy(policyPath: string): Map<string, PolicyEntry> {
  const resolved = path.resolve(policyPath);
  if (!fs.existsSync(resolved)) {
    console.error(`Policy file not found: ${resolved}`);
    process.exit(1);
  }

  const raw = fs.readFileSync(resolved, 'utf-8');
  let config: any;
  if (resolved.endsWith('.json')) {
    config = JSON.parse(raw);
  } else {
    const { parse } = require('yaml');
    config = parse(raw);
  }

  const policy = new Map<string, PolicyEntry>();
  if (config?.tools) {
    for (const [name, pol] of Object.entries(config.tools as Record<string, any>)) {
      policy.set(name, {
        requireBitmask: pol.requireBitmask ?? 0,
        minScore: pol.minScore,
        maxChainDepth: pol.maxChainDepth,
      });
    }
  }
  return policy;
}

function loadReceipts(target: string, receiptDir: string): Receipt[] {
  if (target === 'last' || target === 'all') {
    // Find receipt files in receiptDir
    const receipts = findReceiptFiles(receiptDir);
    if (receipts.length === 0) {
      // Also try stdin if piped
      if (!process.stdin.isTTY) {
        return readReceiptsFromStdin();
      }
      return [];
    }
    if (target === 'last') {
      return [receipts[receipts.length - 1]];
    }
    return receipts;
  }

  // Treat as file path
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    console.error(`Receipt file not found: ${resolved}`);
    process.exit(1);
  }

  return parseReceiptFile(resolved);
}

function findReceiptFiles(dir: string): Receipt[] {
  const resolved = path.resolve(dir);
  const allReceipts: Receipt[] = [];

  // Look for .ndjson files and plain .json files
  if (!fs.existsSync(resolved)) return [];

  const files = fs.readdirSync(resolved).filter(f =>
    f.endsWith('.ndjson') || f.endsWith('.jsonl') || f.includes('receipt')
  ).sort();

  for (const file of files) {
    allReceipts.push(...parseReceiptFile(path.join(resolved, file)));
  }

  // Also check if there's receipt data in the dir itself (from bolyra run stderr capture)
  return allReceipts;
}

function parseReceiptFile(filePath: string): Receipt[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const receipts: Receipt[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.decision) receipts.push(obj as Receipt);
    } catch { /* skip */ }
  }
  return receipts;
}

function readReceiptsFromStdin(): Receipt[] {
  // Synchronous stdin read for piped input
  try {
    const content = fs.readFileSync(0, 'utf-8');
    const receipts: Receipt[] = [];
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed);
        if (obj.decision) receipts.push(obj as Receipt);
      } catch { /* skip */ }
    }
    return receipts;
  } catch {
    return [];
  }
}

function replayReceipt(receipt: Receipt, policy: Map<string, PolicyEntry>): ReplayResult {
  const tool = receipt.toolName ?? '';

  // If no policy provided, everything is allowed
  if (policy.size === 0) {
    return {
      original: receipt,
      replayed: { decision: 'allow', reason: 'no policy (all pass)' },
      changed: receipt.decision !== 'allow',
    };
  }

  const toolPolicy = policy.get(tool);

  // No policy for this tool = allowed (only verified handshake required)
  if (!toolPolicy) {
    return {
      original: receipt,
      replayed: { decision: 'allow', reason: 'no tool policy (verified calls pass)' },
      changed: receipt.decision !== 'allow',
    };
  }

  // Check if the receipt had a score (from allow decisions)
  const score = receipt.score ?? 0;
  const minScore = toolPolicy.minScore ?? 70;

  // For denied receipts, we can't know the bitmask, so check if they'd still be denied
  if (receipt.decision === 'deny') {
    // The original was denied — would the new policy also deny?
    // We can infer: if the tool has a policy and the original reason was permission-related,
    // it would likely still be denied unless the policy was relaxed
    return {
      original: receipt,
      replayed: {
        decision: 'deny',
        reason: `tool requires bitmask ${toolPolicy.requireBitmask} (original denial: ${receipt.reason ?? 'unknown'})`,
      },
      changed: false,
    };
  }

  // For allowed receipts, check if the new policy would still allow
  if (toolPolicy.minScore && score < toolPolicy.minScore) {
    return {
      original: receipt,
      replayed: {
        decision: 'deny',
        reason: `score ${score} < required ${toolPolicy.minScore}`,
      },
      changed: true,
    };
  }

  return {
    original: receipt,
    replayed: { decision: 'allow', reason: 'passes current policy' },
    changed: false,
  };
}

function redactResult(result: ReplayResult): any {
  return {
    original: {
      decision: result.original.decision,
      toolName: result.original.toolName,
      score: result.original.score,
      reason: result.original.reason,
      did: result.original.did ? '***redacted***' : undefined,
      timestamp: result.original.timestamp ? '***redacted***' : undefined,
    },
    replayed: result.replayed,
    changed: result.changed,
  };
}

function printReplayTable(results: ReplayResult[], showDiff: boolean, redact: boolean, policyPath?: string) {
  const policyLabel = policyPath ? path.basename(policyPath) : '(none)';

  console.log('Bolyra replay');
  console.log(`  Receipts:  ${results.length}`);
  console.log(`  Policy:    ${policyLabel}`);
  console.log('');

  if (showDiff) {
    // Show only changed decisions
    const changed = results.filter(r => r.changed);
    if (changed.length === 0) {
      console.log('No changes — all decisions match the current policy.');
      return;
    }

    console.log(`${changed.length} decision(s) would change:\n`);
    console.log(
      pad('TOOL', 30) +
      pad('ORIGINAL', 12) +
      pad('REPLAYED', 12) +
      'REASON'
    );
    console.log('-'.repeat(80));

    for (const r of changed) {
      const tool = r.original.toolName ?? '(unknown)';
      const orig = colorDecision(r.original.decision);
      const repl = colorDecision(r.replayed.decision);
      const reason = r.replayed.reason ?? '';
      console.log(pad(tool, 30) + pad(orig, 21) + pad(repl, 21) + reason);
    }
  } else {
    // Show all
    console.log(
      pad('TOOL', 30) +
      pad('ORIGINAL', 12) +
      pad('REPLAYED', 12) +
      pad('CHANGED', 10) +
      'DETAIL'
    );
    console.log('-'.repeat(90));

    for (const r of results) {
      const tool = r.original.toolName ?? '(unknown)';
      const orig = colorDecision(r.original.decision);
      const repl = colorDecision(r.replayed.decision);
      const changed = r.changed ? '\x1b[33m→ YES\x1b[0m' : '  no';
      const did = redact ? '' : (r.original.did?.slice(-12) ?? '');
      const detail = r.replayed.reason ?? '';
      console.log(pad(tool, 30) + pad(orig, 21) + pad(repl, 21) + pad(changed, 14) + detail);
    }
  }

  // Summary
  const totalChanged = results.filter(r => r.changed).length;
  const denyToAllow = results.filter(r => r.changed && r.original.decision === 'deny' && r.replayed.decision === 'allow').length;
  const allowToDeny = results.filter(r => r.changed && r.original.decision === 'allow' && r.replayed.decision === 'deny').length;

  console.log('');
  console.log(`Summary: ${totalChanged}/${results.length} decisions changed`);
  if (denyToAllow > 0) console.log(`  ${denyToAllow} deny → allow (policy relaxed)`);
  if (allowToDeny > 0) console.log(`  ${allowToDeny} allow → deny (policy tightened)`);
}

function colorDecision(d: string): string {
  if (d === 'allow') return '\x1b[32mALLOW\x1b[0m';
  if (d === 'deny') return '\x1b[31mDENY\x1b[0m';
  return d;
}

function pad(s: string, width: number): string {
  return s.padEnd(width);
}
