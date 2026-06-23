/**
 * bolyra shield test — safety test runner for MCP servers.
 *
 * Connects to an MCP server, fetches its tools, and runs safety checks
 * against a preset (base-mcp for money-moving plugins).
 *
 * Usage:
 *   bolyra shield test --preset base-mcp --server "npm run mcp"
 *   bolyra shield test --preset base-mcp --url http://localhost:3000/mcp
 *   bolyra shield test --server "npx some-mcp" --format json
 */

import { spawn, ChildProcess } from 'child_process';
import * as readline from 'readline';
import { parseArgs } from 'node:util';

const HELP = `
bolyra shield test — safety test runner for MCP servers

Usage:
  bolyra shield test --server "<command>" [options]
  bolyra shield test --url <http-endpoint> [options]

Options:
  --server <cmd>     Spawn stdio MCP server and test it
  --url <url>        Test an HTTP MCP server
  --preset <name>    Safety preset: base-mcp (default), generic
  --format <fmt>     Output: table (default), json, badge
  --help             Show this help

Presets:
  base-mcp           Money-moving MCP plugins (wallets, swaps, transfers, NFTs)
  generic            General-purpose MCP servers

Examples:
  bolyra shield test --server "npx base-mcp" --preset base-mcp
  bolyra shield test --url http://localhost:3000/mcp
`.trim();

// ── Safety checks ──────────────────────────────────────────────

interface Tool {
  name: string;
  description?: string;
  inputSchema?: any;
}

interface CheckResult {
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
}

const FINANCIAL_KEYWORDS = [
  'transfer', 'send', 'swap', 'trade', 'buy', 'sell', 'mint', 'burn',
  'deploy', 'approve', 'revoke', 'bridge', 'stake', 'unstake', 'withdraw',
  'deposit', 'pay', 'purchase', 'order', 'bid', 'list', 'delist',
];

const FINANCIAL_PARAMS = ['amount', 'value', 'price', 'quantity', 'token', 'asset'];
const RECIPIENT_PARAMS = ['to', 'recipient', 'address', 'destination'];
const CHAIN_PARAMS = ['chain', 'network', 'chainId', 'chain_id'];
const APPROVAL_PARAMS = ['confirm', 'approval', 'approve', 'dryRun', 'dry_run', 'simulate'];
const SLIPPAGE_PARAMS = ['slippage', 'max_slippage', 'slippage_bps', 'max_slippage_bps', 'slippageTolerance'];

function isFinancialTool(tool: Tool): boolean {
  const name = tool.name.toLowerCase();
  const desc = (tool.description ?? '').toLowerCase();
  return FINANCIAL_KEYWORDS.some(k => name.includes(k) || desc.includes(k));
}

function getSchemaProps(tool: Tool): string[] {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== 'object') return [];
  const props = schema.properties;
  if (!props || typeof props !== 'object') return [];
  return Object.keys(props);
}

function runBaseMcpChecks(tools: Tool[]): CheckResult[] {
  const results: CheckResult[] = [];

  // Check 1: Tool schemas exist
  const toolsWithSchema = tools.filter(t => t.inputSchema && Object.keys(t.inputSchema).length > 0);
  if (toolsWithSchema.length === tools.length) {
    results.push({ name: 'Tool schemas defined', status: 'PASS', detail: `${tools.length}/${tools.length} tools have input schemas` });
  } else {
    const missing = tools.filter(t => !t.inputSchema || Object.keys(t.inputSchema).length === 0).map(t => t.name);
    results.push({ name: 'Tool schemas defined', status: 'WARN', detail: `${toolsWithSchema.length}/${tools.length} have schemas. Missing: ${missing.join(', ')}` });
  }

  // Check 2: Financial tools identified
  const financialTools = tools.filter(isFinancialTool);
  if (financialTools.length > 0) {
    results.push({ name: 'Financial tools identified', status: 'PASS', detail: `${financialTools.length} tool(s): ${financialTools.map(t => t.name).join(', ')}` });
  } else {
    results.push({ name: 'Financial tools identified', status: 'WARN', detail: 'No financial tools detected. If this server moves money, tool names may need clearer naming.' });
  }

  // Check 3: Financial tools expose amount/value params
  for (const tool of financialTools) {
    const props = getSchemaProps(tool);
    const hasAmount = FINANCIAL_PARAMS.some(p => props.some(prop => prop.toLowerCase().includes(p)));
    if (hasAmount) {
      results.push({ name: `${tool.name}: amount/value param`, status: 'PASS', detail: 'Exposes amount or value parameter' });
    } else {
      results.push({ name: `${tool.name}: amount/value param`, status: 'WARN', detail: 'No amount/value parameter found. Agents may not know what they are spending.' });
    }
  }

  // Check 4: Financial tools expose recipient
  for (const tool of financialTools) {
    const props = getSchemaProps(tool);
    const name = tool.name.toLowerCase();
    // Only check for recipient on transfer/send-like tools
    if (name.includes('transfer') || name.includes('send') || name.includes('bridge') || name.includes('pay')) {
      const hasRecipient = RECIPIENT_PARAMS.some(p => props.some(prop => prop.toLowerCase().includes(p)));
      if (hasRecipient) {
        results.push({ name: `${tool.name}: recipient param`, status: 'PASS', detail: 'Exposes recipient/destination parameter' });
      } else {
        results.push({ name: `${tool.name}: recipient param`, status: 'WARN', detail: 'No recipient parameter found. Agent may not know where funds are going.' });
      }
    }
  }

  // Check 5: Chain/network parameter for multi-chain tools
  const hasChainParam = tools.some(t => {
    const props = getSchemaProps(t);
    return CHAIN_PARAMS.some(p => props.some(prop => prop.toLowerCase().includes(p)));
  });
  if (hasChainParam) {
    results.push({ name: 'Chain/network parameter', status: 'PASS', detail: 'At least one tool exposes chain/network parameter' });
  } else {
    results.push({ name: 'Chain/network parameter', status: 'WARN', detail: 'No chain/network parameter found. May cause cross-chain confusion.' });
  }

  // Check 6: Slippage protection on swap tools
  const swapTools = tools.filter(t => {
    const name = t.name.toLowerCase();
    return name.includes('swap') || name.includes('trade') || name.includes('exchange');
  });
  for (const tool of swapTools) {
    const props = getSchemaProps(tool);
    const hasSlippage = SLIPPAGE_PARAMS.some(p => props.some(prop => prop.toLowerCase().includes(p)));
    if (hasSlippage) {
      results.push({ name: `${tool.name}: slippage protection`, status: 'PASS', detail: 'Exposes slippage parameter' });
    } else {
      results.push({ name: `${tool.name}: slippage protection`, status: 'WARN', detail: 'No slippage parameter. Agents may accept unfavorable rates.' });
    }
  }

  // Check 7: No tools with overly broad names
  const broadNames = tools.filter(t => {
    const name = t.name.toLowerCase();
    return name === 'execute' || name === 'run' || name === 'do' || name === 'action';
  });
  if (broadNames.length === 0) {
    results.push({ name: 'No overly broad tool names', status: 'PASS', detail: 'All tool names are specific' });
  } else {
    results.push({ name: 'No overly broad tool names', status: 'FAIL', detail: `Broad tool names: ${broadNames.map(t => t.name).join(', ')}. These are hard to scope with permissions.` });
  }

  // Check 8: Tool count is reasonable
  if (tools.length <= 50) {
    results.push({ name: 'Tool count', status: 'PASS', detail: `${tools.length} tools (reasonable)` });
  } else {
    results.push({ name: 'Tool count', status: 'WARN', detail: `${tools.length} tools. Large tool surfaces increase agent confusion risk.` });
  }

  // Check 9: Read/write separation possible
  const readTools = tools.filter(t => {
    const name = t.name.toLowerCase();
    return name.includes('get') || name.includes('list') || name.includes('fetch') || name.includes('query') || name.includes('search') || name.includes('check') || name.includes('view');
  });
  if (readTools.length > 0 && readTools.length < tools.length) {
    results.push({ name: 'Read/write separation', status: 'PASS', detail: `${readTools.length} read-only, ${tools.length - readTools.length} write/action tools. Can be split into permission tiers.` });
  } else if (readTools.length === 0) {
    results.push({ name: 'Read/write separation', status: 'WARN', detail: 'No clearly read-only tools found. All tools may need financial permissions.' });
  } else {
    results.push({ name: 'Read/write separation', status: 'PASS', detail: 'All tools appear read-only' });
  }

  // Check 10: Suggested permission tiers
  const tiers = {
    READ_DATA: readTools.map(t => t.name),
    WRITE_DATA: tools.filter(t => !readTools.includes(t) && !isFinancialTool(t)).map(t => t.name),
    FINANCIAL: financialTools.map(t => t.name),
  };
  results.push({
    name: 'Suggested permission tiers',
    status: 'PASS',
    detail: `READ_DATA: ${tiers.READ_DATA.length}, WRITE_DATA: ${tiers.WRITE_DATA.length}, FINANCIAL: ${tiers.FINANCIAL.length}`,
  });

  return results;
}

function runGenericChecks(tools: Tool[]): CheckResult[] {
  // Subset of base-mcp checks without financial-specific ones
  const results: CheckResult[] = [];

  const toolsWithSchema = tools.filter(t => t.inputSchema && Object.keys(t.inputSchema).length > 0);
  results.push({
    name: 'Tool schemas defined',
    status: toolsWithSchema.length === tools.length ? 'PASS' : 'WARN',
    detail: `${toolsWithSchema.length}/${tools.length} tools have input schemas`,
  });

  const broadNames = tools.filter(t => ['execute', 'run', 'do', 'action'].includes(t.name.toLowerCase()));
  results.push({
    name: 'No overly broad tool names',
    status: broadNames.length === 0 ? 'PASS' : 'FAIL',
    detail: broadNames.length === 0 ? 'All tool names are specific' : `Broad: ${broadNames.map(t => t.name).join(', ')}`,
  });

  results.push({
    name: 'Tool count',
    status: tools.length <= 50 ? 'PASS' : 'WARN',
    detail: `${tools.length} tools`,
  });

  return results;
}

// ── MCP connection ─────────────────────────────────────────────

async function fetchToolsStdio(serverCmd: string): Promise<Tool[]> {
  return new Promise((resolve, reject) => {
    const parts = serverCmd.split(/\s+/);
    const child = spawn(parts[0], parts.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });

    const rl = readline.createInterface({ input: child.stdout! });
    const timeout = setTimeout(() => { child.kill(); reject(new Error('Server timeout')); }, 15000);

    // Send initialize
    child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1, params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'bolyra-shield-test', version: '0.1.0' } } }) + '\n');

    let initialized = false;
    rl.on('line', (line: string) => {
      try {
        const msg = JSON.parse(line);
        if (msg.id === 1 && !initialized) {
          initialized = true;
          // Send tools/list
          child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 2 }) + '\n');
        }
        if (msg.id === 2 && msg.result?.tools) {
          clearTimeout(timeout);
          child.kill();
          resolve(msg.result.tools);
        }
      } catch { /* skip */ }
    });

    child.on('error', (err) => { clearTimeout(timeout); reject(err); });
    child.on('exit', () => { clearTimeout(timeout); });
  });
}

async function fetchToolsHttp(url: string): Promise<Tool[]> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
  });
  const body = await res.json() as any;
  return body.result?.tools ?? [];
}

// ── Output ─────────────────────────────────────────────────────

function printTable(results: CheckResult[], tools: Tool[], preset: string) {
  const pass = results.filter(r => r.status === 'PASS').length;
  const warn = results.filter(r => r.status === 'WARN').length;
  const fail = results.filter(r => r.status === 'FAIL').length;

  console.log(`Bolyra Base MCP Safety Report`);
  console.log(`Preset: ${preset} | Tools: ${tools.length}\n`);

  for (const r of results) {
    const icon = r.status === 'PASS' ? '\x1b[32mPASS\x1b[0m' :
                 r.status === 'WARN' ? '\x1b[33mWARN\x1b[0m' :
                 '\x1b[31mFAIL\x1b[0m';
    console.log(`${icon}  ${r.name}`);
    console.log(`      ${r.detail}`);
  }

  console.log(`\nSummary: ${pass} passed, ${warn} warnings, ${fail} failures`);

  if (fail > 0) {
    console.log('\x1b[31mFix failures before deploying.\x1b[0m');
  } else if (warn > 0) {
    console.log('\x1b[33mPassed with warnings. Review before deploying.\x1b[0m');
  } else {
    console.log('\x1b[32mAll checks passed.\x1b[0m');
  }
}

function printBadge(results: CheckResult[]) {
  const fail = results.filter(r => r.status === 'FAIL').length;
  const warn = results.filter(r => r.status === 'WARN').length;

  let badge: string;
  if (fail > 0) {
    badge = '![Bolyra Shield](https://img.shields.io/badge/Bolyra_Shield-FAIL-red)';
  } else if (warn > 0) {
    badge = '![Bolyra Shield](https://img.shields.io/badge/Bolyra_Shield-PASS_with_warnings-yellow)';
  } else {
    badge = '![Bolyra Shield](https://img.shields.io/badge/Bolyra_Shield-PASS-brightgreen)';
  }

  console.log('\nBadge markdown:');
  console.log(badge);
}

// ── Main ───────────────────────────────────────────────────────

export async function run(argv: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        server: { type: 'string' },
        url: { type: 'string' },
        preset: { type: 'string', default: 'base-mcp' },
        format: { type: 'string', default: 'table' },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  if (parsed.values.help) { console.log(HELP); process.exit(0); }

  const serverCmd = parsed.values.server as string | undefined;
  const url = parsed.values.url as string | undefined;
  const preset = parsed.values.preset as string;
  const format = parsed.values.format as string;

  if (!serverCmd && !url) {
    console.error('Error: --server or --url required');
    console.log(HELP);
    process.exit(1);
  }

  // Fetch tools
  let tools: Tool[];
  try {
    if (serverCmd) {
      console.log(`Connecting to stdio server: ${serverCmd}`);
      tools = await fetchToolsStdio(serverCmd);
    } else {
      console.log(`Connecting to HTTP server: ${url}`);
      tools = await fetchToolsHttp(url!);
    }
  } catch (err) {
    console.error(`Failed to connect: ${(err as Error).message}`);
    process.exit(1);
  }

  console.log(`Found ${tools.length} tools\n`);

  // Run checks
  const results = preset === 'base-mcp' ? runBaseMcpChecks(tools) : runGenericChecks(tools);

  // Output
  if (format === 'json') {
    console.log(JSON.stringify({ preset, toolCount: tools.length, tools: tools.map(t => t.name), checks: results }, null, 2));
  } else {
    printTable(results, tools, preset);
    if (format === 'badge') printBadge(results);
  }

  // Exit code
  const failures = results.filter(r => r.status === 'FAIL').length;
  if (failures > 0) process.exitCode = 1;
}
