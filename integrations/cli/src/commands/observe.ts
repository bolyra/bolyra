/**
 * bolyra observe — live activity viewer for bolyra run.
 *
 * Tails receipt NDJSON from stdin or a file and displays
 * formatted allow/deny decisions in real time.
 *
 * Usage:
 *   bolyra run --dev -- npx some-server 2>&1 | bolyra observe
 *   bolyra run --dev --receipt-file /tmp/receipts.ndjson -- npx some-server &
 *   bolyra observe --file /tmp/receipts.ndjson
 */

import * as fs from 'fs';
import * as readline from 'readline';
import { parseArgs } from 'node:util';

const HELP = `
bolyra observe — live activity viewer for bolyra run

Usage:
  bolyra run --dev -- npx server 2>&1 | bolyra observe
  bolyra observe --file /tmp/receipts.ndjson
  bolyra observe --file /tmp/receipts.ndjson --suggest-policy

Options:
  --file <path>       Tail receipts from a file (instead of stdin)
  --suggest-policy    After Ctrl+C, print a suggested shield.yaml
  --output <path>     Write the suggested policy to a file (e.g. shield.yaml)
  --help              Show this help
`.trim();

interface Receipt {
  decision: 'allow' | 'deny';
  toolName?: string;
  did?: string;
  score?: number;
  reason?: string;
  timestamp?: string;
}

interface ToolStats {
  allowed: number;
  denied: number;
  lastDid?: string;
  lastScore?: number;
  lastReason?: string;
  maxBitmaskNeeded: number;
}

export async function run(argv: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        file: { type: 'string' },
        'suggest-policy': { type: 'boolean', default: false },
        output: { type: 'string' },
        help: { type: 'boolean', default: false },
      },
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

  const filePath = parsed.values.file as string | undefined;
  const suggestPolicy = parsed.values['suggest-policy'] as boolean;
  const outputPath = parsed.values.output as string | undefined;

  const toolStats = new Map<string, ToolStats>();
  let totalAllow = 0;
  let totalDeny = 0;

  console.log('Bolyra observe — live activity viewer');
  console.log('Waiting for receipts...\n');
  console.log(
    pad('TIME', 8) +
    pad('DECISION', 10) +
    pad('TOOL', 30) +
    pad('AGENT', 20) +
    'DETAIL'
  );
  console.log('-'.repeat(90));

  // Choose input source
  let input: NodeJS.ReadableStream;
  if (filePath) {
    // Tail the file (wait for it to exist, then stream)
    await waitForFile(filePath);
    input = fs.createReadStream(filePath, { encoding: 'utf-8' });
    // For tailing a growing file, re-open on end
    const startTailing = () => {
      const stream = fs.createReadStream(filePath, {
        encoding: 'utf-8',
        start: fs.statSync(filePath).size,
      });
      const rl = readline.createInterface({ input: stream });
      rl.on('line', (line) => processLine(line, toolStats));
      stream.on('end', () => {
        setTimeout(startTailing, 500);
      });
    };
    // Read existing content first
    const rl = readline.createInterface({ input });
    rl.on('line', (line) => processLine(line, toolStats));
    rl.on('close', startTailing);
  } else {
    // Read from stdin
    if (process.stdin.isTTY) {
      console.log('(reading from stdin — pipe bolyra run stderr here)');
    }
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => processLine(line, toolStats));
    rl.on('close', () => {
      printSummary(toolStats, totalAllow, totalDeny);
      if (suggestPolicy) printSuggestedPolicy(toolStats);
      if (outputPath) writePolicyFile(outputPath, toolStats);
    });
  }

  function processLine(line: string, stats: Map<string, ToolStats>) {
    let receipt: Receipt;
    try {
      receipt = JSON.parse(line.trim());
    } catch {
      return; // skip non-JSON lines (banner, etc.)
    }

    if (!receipt.decision) return;

    const tool = receipt.toolName ?? '(unknown)';
    const ts = receipt.timestamp
      ? new Date(receipt.timestamp).toLocaleTimeString('en-US', { hour12: false })
      : '--:--:--';

    // Update stats
    let st = stats.get(tool);
    if (!st) {
      st = { allowed: 0, denied: 0, maxBitmaskNeeded: 0 };
      stats.set(tool, st);
    }

    if (receipt.decision === 'allow') {
      totalAllow++;
      st.allowed++;
      st.lastDid = receipt.did;
      st.lastScore = receipt.score;
      const icon = '\x1b[32m✓ ALLOW\x1b[0m';
      const did = receipt.did ? receipt.did.slice(-12) : '';
      const detail = `score ${receipt.score ?? '?'}`;
      console.log(pad(ts, 8) + pad(icon, 19) + pad(tool, 30) + pad(did, 20) + detail);
    } else {
      totalDeny++;
      st.denied++;
      st.lastReason = receipt.reason;
      const icon = '\x1b[31m✗ DENY \x1b[0m';
      const reason = receipt.reason ?? 'unknown';
      console.log(pad(ts, 8) + pad(icon, 19) + pad(tool, 30) + pad('', 20) + reason);
    }
  }

  // Handle Ctrl+C gracefully
  process.on('SIGINT', () => {
    console.log('\n');
    printSummary(toolStats, totalAllow, totalDeny);
    if (suggestPolicy) printSuggestedPolicy(toolStats);
    if (outputPath) writePolicyFile(outputPath, toolStats);
    process.exit(0);
  });
}

function pad(s: string, width: number): string {
  return s.padEnd(width);
}

function printSummary(stats: Map<string, ToolStats>, allow: number, deny: number) {
  console.log('Summary');
  console.log(`  Total: ${allow + deny} requests (${allow} allowed, ${deny} denied)`);
  console.log('');
  console.log(pad('TOOL', 30) + pad('ALLOWED', 10) + pad('DENIED', 10));
  console.log('-'.repeat(50));
  for (const [tool, st] of stats) {
    console.log(pad(tool, 30) + pad(String(st.allowed), 10) + pad(String(st.denied), 10));
  }
}

function printSuggestedPolicy(stats: Map<string, ToolStats>) {
  console.log('\nSuggested shield.yaml:\n');
  console.log('tools:');
  for (const [tool, st] of stats) {
    if (st.denied > 0 && st.allowed === 0) {
      // Tool was always denied — probably needs higher permissions
      console.log(`  ${tool}:`);
      console.log(`    requireBitmask: 2    # WRITE_DATA (was always denied)`);
    } else if (st.allowed > 0) {
      console.log(`  ${tool}:`);
      console.log(`    requireBitmask: 1    # READ_DATA`);
    }
  }
}

function writePolicyFile(outPath: string, stats: Map<string, ToolStats>) {
  const lines: string[] = [
    '# shield.yaml — auto-generated by bolyra observe',
    '# Review and adjust bitmasks before enforcing.',
    '',
    'devMode: true',
    '',
    'nonce:',
    '  store: memory',
    '  maxProofAge: 300',
    '',
    'receipts:',
    '  enabled: true',
    '  output: stderr',
    '',
    'tools:',
  ];

  for (const [tool, st] of stats) {
    if (st.denied > 0 && st.allowed === 0) {
      lines.push(`  ${tool}:`);
      lines.push(`    requireBitmask: 2    # WRITE_DATA (was always denied)`);
    } else if (st.allowed > 0) {
      lines.push(`  ${tool}:`);
      lines.push(`    requireBitmask: 1    # READ_DATA`);
    }
  }

  const content = lines.join('\n') + '\n';
  fs.writeFileSync(outPath, content);
  console.log(`\nPolicy written to ${outPath}`);
  console.log(`Next: bolyra run --policy ${outPath} --dev -- <your server command>`);
}

async function waitForFile(path: string, maxWait = 10000): Promise<void> {
  const start = Date.now();
  while (!fs.existsSync(path)) {
    if (Date.now() - start > maxWait) {
      console.error(`File ${path} not found after ${maxWait}ms`);
      process.exit(1);
    }
    await new Promise(r => setTimeout(r, 200));
  }
}
