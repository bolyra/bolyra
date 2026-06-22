// examples/robinhood-demo/src/run-demo.ts
// Demo orchestrator: starts mock Robinhood MCP + Bolyra gateway, runs 4 scenarios.

import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MOCK_PORT = 3100;
const GATEWAY_PORT = 4100;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;

const GATEWAY_BIN = path.resolve(__dirname, '../../../integrations/gateway/dist/cli.js');
const CONFIG_PATH = path.resolve(__dirname, '../gateway.yaml');
const MOCK_SERVER_PATH = path.resolve(__dirname, 'mock-robinhood-mcp.ts');

// ---------------------------------------------------------------------------
// Dev bundle helper
// ---------------------------------------------------------------------------

interface Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  publicSignals: string[];
}

function makeDevBundle(permissionBitmask: number, commitmentSeed: number): string {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const entropy = BigInt(Math.floor(Math.random() * 2 ** 32));
  const nonce = ((nowSec << 64n) | entropy).toString();

  const dummyProof: Proof = {
    pi_a: ['0', '0', '1'],
    pi_b: [['0', '0'], ['0', '0'], ['1', '0']],
    pi_c: ['0', '0', '1'],
    publicSignals: ['0', '0', '0', '0'],
  };

  const bundle = {
    v: 1,
    _dev: true,
    humanProof: { ...dummyProof },
    agentProof: {
      ...dummyProof,
      publicSignals: ['0', '0', '0', String(permissionBitmask)],
    },
    nonce,
    credentialCommitment: String(commitmentSeed),
  };

  return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

// ---------------------------------------------------------------------------
// JSON-RPC helper
// ---------------------------------------------------------------------------

interface ScenarioResult {
  status: number;
  body: unknown;
}

async function callGateway(
  toolName: string,
  toolArgs: Record<string, unknown>,
  authToken: string,
): Promise<ScenarioResult> {
  const rpcBody = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'tools/call',
    params: { name: toolName, arguments: toolArgs },
  };

  const res = await fetch(GATEWAY_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bolyra ${authToken}`,
    },
    body: JSON.stringify(rpcBody),
  });

  const body = await res.json();
  return { status: res.status, body };
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

const children: ChildProcess[] = [];

function startMockServer(): ChildProcess {
  const child = spawn('npx', ['tsx', MOCK_SERVER_PATH], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, MOCK_PORT: String(MOCK_PORT) },
  });
  children.push(child);

  child.stdout?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`  [mock] ${line}`);
  });
  child.stderr?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`  [mock:err] ${line}`);
  });

  return child;
}

function startGateway(): ChildProcess {
  if (!fs.existsSync(GATEWAY_BIN)) {
    console.error(
      `\nGateway CLI not found at ${GATEWAY_BIN}\n` +
        `Build it first:\n  cd integrations/gateway && npm run build\n`,
    );
    process.exit(1);
  }

  const child = spawn('node', [GATEWAY_BIN, '--config', CONFIG_PATH, '--dev'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);

  child.stdout?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`  [gateway] ${line}`);
  });
  child.stderr?.on('data', (data: Buffer) => {
    const line = data.toString().trim();
    if (line) console.log(`  [gateway:err] ${line}`);
  });

  return child;
}

function killAll(): void {
  for (const child of children) {
    try {
      child.kill('SIGTERM');
    } catch {
      // already exited
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

function banner(n: number, title: string): void {
  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Scenario ${n}: ${title}`);
  console.log('='.repeat(70));
}

async function runScenarios(): Promise<void> {
  // -------------------------------------------------------------------
  // Scenario 1: Verified agent reads portfolio
  // -------------------------------------------------------------------
  banner(1, 'Verified agent reads portfolio');

  const traderBundle1 = makeDevBundle(7, 1001); // READ+WRITE+FINANCIAL_SMALL
  const r1 = await callGateway('robinhood_get_portfolio', {}, traderBundle1);

  console.log(`  Status: ${r1.status}`);
  console.log(`  Body:   ${JSON.stringify(r1.body, null, 2)}`);
  console.log(r1.status === 200 ? '  \u2705 PASS — portfolio returned' : '  \u274c FAIL — expected 200');

  // -------------------------------------------------------------------
  // Scenario 2: Verified agent places stock order
  // -------------------------------------------------------------------
  banner(2, 'Verified agent places stock order');

  const traderBundle2 = makeDevBundle(7, 1001); // Fresh bundle, same permissions
  const r2 = await callGateway(
    'robinhood_place_stock_order',
    { symbol: 'AAPL', side: 'buy', quantity: 10, type: 'market' },
    traderBundle2,
  );

  console.log(`  Status: ${r2.status}`);
  console.log(`  Body:   ${JSON.stringify(r2.body, null, 2)}`);
  console.log(r2.status === 200 ? '  \u2705 PASS — order confirmed' : '  \u274c FAIL — expected 200');

  // -------------------------------------------------------------------
  // Scenario 3: Read-only agent blocked from trading
  // -------------------------------------------------------------------
  banner(3, 'Read-only agent blocked from trading');

  const readerBundle = makeDevBundle(1, 2002); // READ_DATA only
  const r3 = await callGateway(
    'robinhood_place_stock_order',
    { symbol: 'AAPL', side: 'buy', quantity: 10, type: 'market' },
    readerBundle,
  );

  console.log(`  Status: ${r3.status}`);
  console.log(`  Body:   ${JSON.stringify(r3.body, null, 2)}`);
  console.log(r3.status === 403 ? '  \ud83d\udeab PASS — permission denied (403)' : '  \u274c FAIL — expected 403');

  // -------------------------------------------------------------------
  // Scenario 4: Replay attack blocked
  // -------------------------------------------------------------------
  banner(4, 'Replay attack blocked (reuse nonce from scenario 1)');

  // Deliberately reuse the EXACT bundle from scenario 1
  const r4 = await callGateway('robinhood_get_portfolio', {}, traderBundle1);

  console.log(`  Status: ${r4.status}`);
  console.log(`  Body:   ${JSON.stringify(r4.body, null, 2)}`);
  console.log(r4.status === 401 ? '  \ud83d\udeab PASS — nonce replay rejected (401)' : '  \u274c FAIL — expected 401');

  // -------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------
  const passed = [
    r1.status === 200,
    r2.status === 200,
    r3.status === 403,
    r4.status === 401,
  ].filter(Boolean).length;

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Summary: ${passed}/4 scenarios passed`);
  console.log('='.repeat(70));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('Bolyra x Robinhood Gateway Demo');
  console.log('Starting servers...\n');

  try {
    startMockServer();
    startGateway();

    // Wait for both servers to be ready
    await sleep(3000);

    await runScenarios();
  } finally {
    console.log('\nShutting down servers...');
    killAll();
    // Give processes a moment to exit cleanly
    await sleep(500);
    process.exit(0);
  }
}

main();
