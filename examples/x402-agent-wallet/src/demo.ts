/**
 * x402 Agent Wallet Guard Demo
 *
 * Shows an agent wallet with human-delegated spend limits
 * auto-paying x402 requests on Base.
 *
 * 6 scenarios:
 * 1. Agent buys NVDA research ($0.50) — authorized
 * 2. Agent buys BTC summary ($0.25) — authorized
 * 3. Agent buys GPU hour ($1.00) — authorized
 * 4. Agent buys premium report ($5.00) — DENIED (exceeds $2.00/request cap)
 * 5. Agent buys market feed ($0.10) — authorized
 * 6. Agent buys more research — DENIED (daily cap exceeded)
 */
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import { BolyraAgentWallet } from './agent-wallet';

const API_PORT = 3300;
const API_URL = `http://localhost:${API_PORT}`;

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

function banner(text: string): void {
  const line = '═'.repeat(64);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function printResult(label: string, result: { status: number; data: any; receipt: any }): void {
  const icon = result.receipt.decision === 'allow' ? '✅' : '🚫';
  console.log(`${icon} ${label}`);
  console.log(`   Decision: ${result.receipt.decision.toUpperCase()}`);
  if (result.receipt.amount) {
    console.log(`   Amount:   $${(result.receipt.amount / 100).toFixed(2)} ${result.receipt.asset || ''}`);
  }
  if (result.receipt.reason) {
    console.log(`   Reason:   ${result.receipt.reason}`);
  }
  console.log(`   Daily:    $${(result.receipt.dailySpent / 100).toFixed(2)} spent, $${(result.receipt.dailyRemaining / 100).toFixed(2)} remaining`);
  console.log(`   Receipt:  ${result.receipt.id}`);
  if (result.data?.data) {
    const preview = JSON.stringify(result.data.data).slice(0, 80);
    console.log(`   Data:     ${preview}...`);
  }
  console.log('');
}

async function main(): Promise<void> {
  const procs: ChildProcess[] = [];

  try {
    banner('x402 Agent Wallet Guard Demo');
    console.log('Human-capped x402 spending for agent wallets on Base.\n');

    // Start paid API server
    const apiProc = spawn('npx', ['tsx', path.join(__dirname, 'paid-api.ts')], {
      env: { ...process.env, API_PORT: String(API_PORT) },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(apiProc);
    apiProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[api] ${d}`));

    await sleep(3000);

    // Create agent wallet with policy
    console.log('Agent Wallet Policy:');
    console.log('  Max per request:  $2.00');
    console.log('  Daily cap:        $2.00');
    console.log('  Allowed assets:   USDC');
    console.log('  Allowed networks: base-sepolia');
    console.log('  Agent DID:        did:bolyra:base-sepolia:0x742d...bDe7');
    console.log('');

    const wallet = new BolyraAgentWallet({
      maxPerRequest: 200,     // $2.00
      dailyCap: 200,          // $2.00
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
      agentDid: 'did:bolyra:base-sepolia:0x742d35Cc6634C0532925a3b844Bc9e7595f8bDe7',
    });

    // ── Scenario 1: NVDA research ($0.50) ──
    banner('Scenario 1: Agent buys NVDA research ($0.50)');
    const s1 = await wallet.fetch(`${API_URL}/research/nvda`);
    printResult('NVDA research', s1);

    // ── Scenario 2: BTC summary ($0.25) ──
    banner('Scenario 2: Agent buys BTC market summary ($0.25)');
    const s2 = await wallet.fetch(`${API_URL}/research/btc`);
    printResult('BTC summary', s2);

    // ── Scenario 3: GPU hour ($1.00) ──
    banner('Scenario 3: Agent buys 1h GPU inference ($1.00)');
    const s3 = await wallet.fetch(`${API_URL}/compute/gpu-hour`);
    printResult('GPU hour', s3);

    // ── Scenario 4: Premium report ($5.00) — OVER PER-REQUEST CAP ──
    banner('Scenario 4: Agent tries premium report ($5.00)');
    const s4 = await wallet.fetch(`${API_URL}/premium/report`);
    printResult('Premium report → BLOCKED (exceeds $2.00/request cap)', s4);

    // ── Scenario 5: Market feed ($0.10) ──
    banner('Scenario 5: Agent buys market data feed ($0.10)');
    const s5 = await wallet.fetch(`${API_URL}/data/market-feed`);
    printResult('Market feed', s5);

    // ── Scenario 6: More research — OVER DAILY CAP ──
    banner('Scenario 6: Agent tries more research ($0.50)');
    const s6 = await wallet.fetch(`${API_URL}/research/nvda`);
    printResult('More research → BLOCKED (daily cap exceeded)', s6);

    // ── Summary ──
    banner('Demo Complete');
    console.log('Scenario 1: ✅ NVDA research ($0.50) — authorized');
    console.log('Scenario 2: ✅ BTC summary ($0.25) — authorized');
    console.log('Scenario 3: ✅ GPU hour ($1.00) — authorized');
    console.log('Scenario 4: 🚫 Premium report ($5.00) — per-request cap exceeded');
    console.log('Scenario 5: ✅ Market feed ($0.10) — authorized');
    console.log('Scenario 6: 🚫 More research ($0.50) — daily cap exceeded');
    console.log('');
    console.log(`Total spent: $${(wallet.getDailySpent() / 100).toFixed(2)} / $2.00 daily cap`);
    console.log(`Receipts: ${wallet.getReceipts().length} (${wallet.getReceipts().filter(r => r.decision === 'allow').length} allowed, ${wallet.getReceipts().filter(r => r.decision === 'deny').length} denied)`);
    console.log('');
    console.log('Agent wallet = policy-enforced spender, not just a key.');
    console.log('Every decision has a signed receipt with agent DID, amount, and reason.');

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
