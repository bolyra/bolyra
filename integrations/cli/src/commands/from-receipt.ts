/**
 * bolyra dev from-receipt — generate test fixtures from receipts.
 *
 * Takes a receipt file or session ID and generates:
 *   - Dev identities matching the receipt's permission levels
 *   - A shield.yaml policy matching the observed tool access
 *   - A test script that replays the exact tool calls
 *
 * Usage:
 *   bolyra dev from-receipt last
 *   bolyra dev from-receipt <session-id>
 *   bolyra dev from-receipt ./receipts.ndjson
 *   bolyra dev from-receipt last --output-dir ./test-fixtures
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseArgs } from 'node:util';
import {
  getLatestSession,
  getSession,
  readSessionReceipts,
  type ReceiptEntry,
} from './replay-store';

const HELP = `
bolyra dev from-receipt — generate test fixtures from receipts

Usage:
  bolyra dev from-receipt last [options]
  bolyra dev from-receipt <session-id> [options]
  bolyra dev from-receipt <receipt-file> [options]

Options:
  --output-dir <dir>   Output directory (default: ./bolyra-fixtures)
  --help               Show this help

Generates:
  - shield.yaml        Policy matching observed tool access
  - dev-bundles.json   Dev proof bundles for each permission level seen
  - replay-test.sh     Script to replay the exact tool calls via curl
`.trim();

export async function run(argv: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        'output-dir': { type: 'string', default: './bolyra-fixtures' },
        help: { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  if (parsed.values.help || parsed.positionals.length === 0) {
    console.log(HELP);
    process.exit(parsed.values.help ? 0 : 1);
  }

  const target = parsed.positionals[0];
  const outputDir = parsed.values['output-dir'] as string;

  // Load receipts
  const receipts = loadReceipts(target);
  if (receipts.length === 0) {
    console.error('No receipts found.');
    process.exit(1);
  }

  // Analyze receipts
  const tools = analyzeReceipts(receipts);

  // Generate fixtures
  fs.mkdirSync(outputDir, { recursive: true });

  // 1. shield.yaml
  const policyContent = generatePolicy(tools);
  fs.writeFileSync(path.join(outputDir, 'shield.yaml'), policyContent);

  // 2. dev-bundles.json
  const bundles = generateDevBundles(tools);
  fs.writeFileSync(path.join(outputDir, 'dev-bundles.json'), JSON.stringify(bundles, null, 2));

  // 3. replay-test.sh
  const testScript = generateReplayScript(receipts, tools);
  const scriptPath = path.join(outputDir, 'replay-test.sh');
  fs.writeFileSync(scriptPath, testScript);
  fs.chmodSync(scriptPath, '755');

  // 4. Summary
  console.log('Generated test fixtures:');
  console.log(`  ${path.join(outputDir, 'shield.yaml')}       — policy from observed traffic`);
  console.log(`  ${path.join(outputDir, 'dev-bundles.json')}  — dev proof bundles`);
  console.log(`  ${path.join(outputDir, 'replay-test.sh')}    — replay script`);
  console.log('');
  console.log(`Tools observed: ${tools.size}`);
  for (const [name, info] of tools) {
    console.log(`  ${name}: ${info.allowed}x allowed, ${info.denied}x denied → bitmask ${info.suggestedBitmask}`);
  }
  console.log('');
  console.log(`Next: bash ${path.join(outputDir, 'replay-test.sh')}`);
}

interface ToolInfo {
  allowed: number;
  denied: number;
  suggestedBitmask: number;
  maxScore: number;
  minScore: number;
  reasons: string[];
}

function loadReceipts(target: string): ReceiptEntry[] {
  if (target === 'last') {
    const session = getLatestSession();
    if (session) return readSessionReceipts(session.id);
    return [];
  }

  // Try as session ID
  const session = getSession(target);
  if (session) return readSessionReceipts(session.id);

  // Try as file path
  const resolved = path.resolve(target);
  if (fs.existsSync(resolved)) {
    const content = fs.readFileSync(resolved, 'utf-8');
    const receipts: ReceiptEntry[] = [];
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed);
        if (obj.decision) receipts.push(obj);
      } catch { /* skip */ }
    }
    return receipts;
  }

  return [];
}

function analyzeReceipts(receipts: ReceiptEntry[]): Map<string, ToolInfo> {
  const tools = new Map<string, ToolInfo>();

  for (const r of receipts) {
    const name = r.toolName ?? '(unknown)';
    let info = tools.get(name);
    if (!info) {
      info = { allowed: 0, denied: 0, suggestedBitmask: 1, maxScore: 0, minScore: 100, reasons: [] };
      tools.set(name, info);
    }

    if (r.decision === 'allow') {
      info.allowed++;
      if (r.score !== undefined) {
        info.maxScore = Math.max(info.maxScore, r.score);
        info.minScore = Math.min(info.minScore, r.score);
      }
    } else {
      info.denied++;
      if (r.reason) info.reasons.push(r.reason);
    }
  }

  // Infer bitmasks from tool names
  for (const [name, info] of tools) {
    if (name.includes('write') || name.includes('delete') || name.includes('cancel') || name.includes('update')) {
      info.suggestedBitmask = 2; // WRITE_DATA
    } else if (name.includes('order') || name.includes('trade') || name.includes('place') || name.includes('buy') || name.includes('sell')) {
      info.suggestedBitmask = 4; // FINANCIAL_SMALL
    } else if (name.includes('option') || name.includes('crypto') || name.includes('spread')) {
      info.suggestedBitmask = 8; // FINANCIAL_MEDIUM
    } else {
      info.suggestedBitmask = 1; // READ_DATA
    }
  }

  return tools;
}

function generatePolicy(tools: Map<string, ToolInfo>): string {
  const lines = [
    '# shield.yaml — generated from receipt analysis',
    '# Review bitmasks before enforcing in production.',
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

  for (const [name, info] of tools) {
    const label = bitmaskLabel(info.suggestedBitmask);
    lines.push(`  ${name}:`);
    lines.push(`    requireBitmask: ${info.suggestedBitmask}    # ${label} (${info.allowed} allowed, ${info.denied} denied)`);
  }

  return lines.join('\n') + '\n';
}

function generateDevBundles(tools: Map<string, ToolInfo>): Record<string, any> {
  // Collect unique bitmask levels needed
  const bitmasks = new Set<number>();
  for (const info of tools.values()) {
    bitmasks.add(info.suggestedBitmask);
  }

  const bundles: Record<string, any> = {};

  for (const bitmask of [...bitmasks].sort()) {
    const label = bitmaskLabel(bitmask);
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    const entropy = BigInt(bitmask * 1000 + 1);
    const nonce = ((nowSec << 64n) | entropy).toString();

    bundles[label] = {
      description: `Dev bundle with ${label} (bitmask ${bitmask})`,
      bitmask,
      bundle: {
        v: 1,
        _dev: true,
        humanProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0','0'] },
        agentProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0', String(bitmask)] },
        nonce,
        credentialCommitment: String(bitmask),
      },
      note: 'Nonce is time-bound. Regenerate before use: nonce = (unix_seconds << 64) | random',
    };
  }

  return bundles;
}

function generateReplayScript(receipts: ReceiptEntry[], tools: Map<string, ToolInfo>): string {
  const lines = [
    '#!/bin/bash',
    '# replay-test.sh — generated from receipt analysis',
    '# Replays observed tool calls against a bolyra run instance.',
    '#',
    '# Start your server first:',
    '#   bolyra run --policy ./shield.yaml --dev -- <your server command>',
    '#',
    '# Then run this script:',
    '#   bash replay-test.sh',
    '',
    'ENDPOINT="${BOLYRA_ENDPOINT:-http://localhost:4100}"',
    '',
  ];

  // Generate one curl per unique allowed tool call
  const seen = new Set<string>();
  let testNum = 0;

  for (const r of receipts) {
    const tool = r.toolName ?? '';
    if (!tool || seen.has(tool)) continue;
    seen.add(tool);
    testNum++;

    const info = tools.get(tool);
    const bitmask = info?.suggestedBitmask ?? 1;

    lines.push(`# Test ${testNum}: ${tool} (bitmask ${bitmask})`);
    lines.push(`echo "Test ${testNum}: ${tool} (expect ${r.decision})"`);

    if (r.decision === 'allow') {
      lines.push(`BUNDLE=$(cat dev-bundles.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=[k for k in d if d[k]['bitmask']>=${bitmask}]; print(json.dumps(d[k[0]]['bundle']) if k else '{}')" | base64)`);
      lines.push(`curl -s -X POST "$ENDPOINT" \\`);
      lines.push(`  -H "Content-Type: application/json" \\`);
      lines.push(`  -H "Authorization: Bolyra $BUNDLE" \\`);
      lines.push(`  -d '{"jsonrpc":"2.0","method":"tools/call","id":${testNum},"params":{"name":"${tool}","arguments":{}}}' | python3 -m json.tool 2>/dev/null | head -5`);
    } else {
      lines.push(`curl -s -X POST "$ENDPOINT" \\`);
      lines.push(`  -H "Content-Type: application/json" \\`);
      lines.push(`  -d '{"jsonrpc":"2.0","method":"tools/call","id":${testNum},"params":{"name":"${tool}","arguments":{}}}' | python3 -m json.tool 2>/dev/null | head -5`);
    }
    lines.push(`echo ""`);
    lines.push('');
  }

  lines.push(`echo "Done: ${testNum} tests"`);

  return lines.join('\n') + '\n';
}

function bitmaskLabel(bitmask: number): string {
  switch (bitmask) {
    case 1: return 'READ_DATA';
    case 2: return 'WRITE_DATA';
    case 3: return 'READ+WRITE';
    case 4: return 'FINANCIAL_SMALL';
    case 8: return 'FINANCIAL_MEDIUM';
    case 16: return 'FINANCIAL_UNLIMITED';
    default: return `bitmask_${bitmask}`;
  }
}
