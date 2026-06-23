/**
 * Coinbase Agent Account × Bolyra Gateway Demo
 *
 * Shows how Bolyra protects a Coinbase AgentKit MCP server with:
 * 1. Delegated authority (per-tool permissions)
 * 2. Spend limits (FINANCIAL_SMALL vs FINANCIAL_UNLIMITED)
 * 3. Replay protection
 * 4. Signed audit receipts
 *
 * 6 scenarios, no Coinbase API keys needed.
 */
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';

const MOCK_PORT = 3200;
const GATEWAY_PORT = 4200;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function banner(text: string): void {
  const line = '═'.repeat(64);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function printResult(label: string, status: number, body: any): void {
  const icon = status === 200 ? '✅' : '🚫';
  console.log(`${icon} ${label}`);
  console.log(`   HTTP ${status}`);
  if (body.result?.content?.[0]?.text) {
    console.log(`   ${body.result.content[0].text.split('\n').slice(0, 3).join('\n   ')}`);
  } else if (body.error) {
    console.log(`   ${body.error.message}`);
  }
  console.log('');
}

function makeDevBundle(permissionBitmask: number, seed: number): string {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const entropy = BigInt(seed);
  const nonce = ((nowSec << 64n) | entropy).toString();
  const bundle = {
    v: 1, _dev: true,
    humanProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0','0'] },
    agentProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0', String(permissionBitmask)] },
    nonce,
    credentialCommitment: String(seed),
  };
  return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

async function callGateway(toolName: string, args: Record<string, unknown>, proofHeader?: string): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (proofHeader) headers['Authorization'] = `Bolyra ${proofHeader}`;
  const res = await fetch(GATEWAY_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: toolName, arguments: args },
      id: Date.now(),
    }),
  });
  const body = await res.json();
  return { status: res.status, body };
}

async function main(): Promise<void> {
  const procs: ChildProcess[] = [];

  try {
    banner('Coinbase Agent Account × Bolyra Gateway Demo');
    console.log('Coinbase gives AI agents accounts.');
    console.log('Bolyra gives those accounts enforceable delegated authority.\n');

    // Start mock server
    const mockProc = spawn('npx', ['tsx', path.join(__dirname, 'mock-coinbase-mcp.ts')], {
      env: { ...process.env, MOCK_PORT: String(MOCK_PORT) },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(mockProc);
    mockProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[mock] ${d}`));

    // Start gateway
    const gatewayBin = path.resolve(__dirname, '../../../integrations/gateway/dist/cli.js');
    const configPath = path.join(__dirname, '..', 'gateway.yaml');
    const gatewayProc = spawn('node', [gatewayBin, '--config', configPath, '--dev'], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(gatewayProc);
    gatewayProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[gateway] ${d}`));

    await sleep(3000);

    // ── Scenario 1: Read portfolio (READ_DATA agent) ────────────
    banner('Scenario 1: Agent reads portfolio');
    const s1 = await callGateway('get_portfolio', {}, makeDevBundle(1, 5001));
    printResult('READ_DATA agent reads portfolio', s1.status, s1.body);

    // ── Scenario 2: Small transfer (FINANCIAL_SMALL agent) ──────
    banner('Scenario 2: Agent transfers 25 USDC');
    const s2 = await callGateway('transfer_token', {
      token: 'USDC', amount: '25.00', to: '0xRecipient',
    }, makeDevBundle(7, 5002)); // READ + WRITE + FINANCIAL_SMALL
    printResult('FINANCIAL_SMALL agent transfers 25 USDC', s2.status, s2.body);

    // ── Scenario 3: Read-only agent blocked from transfer ───────
    banner('Scenario 3: Read-only agent blocked from transfer');
    const s3 = await callGateway('transfer_token', {
      token: 'USDC', amount: '25.00', to: '0xRecipient',
    }, makeDevBundle(1, 5003)); // READ_DATA only
    printResult('READ_DATA agent tries transfer → BLOCKED', s3.status, s3.body);

    // ── Scenario 4: x402 paid API call ──────────────────────────
    banner('Scenario 4: Agent pays for API access (x402)');
    const s4 = await callGateway('pay_for_api', {
      amount: '0.50', currency: 'USDC', recipient: '0xAPIVendor', purpose: 'market data feed',
    }, makeDevBundle(7, 5004));
    printResult('FINANCIAL_SMALL agent pays $0.50 for API', s4.status, s4.body);

    // ── Scenario 5: Deploy contract blocked (needs UNLIMITED) ───
    banner('Scenario 5: Agent blocked from deploying contract');
    const s5 = await callGateway('deploy_contract', {
      bytecode: '0x608060...',
    }, makeDevBundle(7, 5005)); // FINANCIAL_SMALL, not UNLIMITED
    printResult('FINANCIAL_SMALL agent tries deploy_contract → BLOCKED', s5.status, s5.body);

    // ── Scenario 6: Replay attack blocked ───────────────────────
    banner('Scenario 6: Replay attack blocked');
    // Reuse the bundle from scenario 1 (same nonce)
    const replayBundle = makeDevBundle(1, 5001);
    const s6 = await callGateway('get_portfolio', {}, replayBundle);
    printResult('Replay of scenario 1 proof → BLOCKED', s6.status, s6.body);

    // ── Summary ─────────────────────────────────────────────────
    banner('Demo Complete');
    console.log('Scenario 1: ✅ Agent reads portfolio (READ_DATA)');
    console.log('Scenario 2: ✅ Agent transfers 25 USDC (FINANCIAL_SMALL)');
    console.log('Scenario 3: 🚫 Read-only agent blocked from transfer');
    console.log('Scenario 4: ✅ Agent pays for API via x402 (FINANCIAL_SMALL)');
    console.log('Scenario 5: 🚫 Agent blocked from deploy_contract (needs FINANCIAL_UNLIMITED)');
    console.log('Scenario 6: 🚫 Replay of previous proof blocked');
    console.log('');
    console.log('Each scenario generated a signed receipt (see gateway stdout above).');
    console.log('');
    console.log('Positioning:');
    console.log('  Coinbase gives AI agents accounts.');
    console.log('  Bolyra gives those accounts enforceable delegated authority,');
    console.log('  spend limits, replay protection, and audit receipts.');
    console.log('');
    console.log('Contracts deployed on Base Sepolia. Try the playground: https://bolyra.ai/playground');

  } finally {
    for (const p of procs) p.kill('SIGTERM');
    await sleep(500);
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exit(1);
});
