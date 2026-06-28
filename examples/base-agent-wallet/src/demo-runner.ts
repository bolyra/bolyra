/**
 * Base Agent Wallet Demo Runner
 *
 * 6-scenario orchestrator demonstrating human-delegated spending on Base:
 *
 * Phase 1 - Human Delegation:
 *   Set up delegation with $2.00/request cap, $2.00/day cap, USDC on base-sepolia.
 *
 * Phase 2 - Agent Transacts:
 *   1. Agent buys NVDA research ($0.50)      -> ALLOW
 *   2. Agent buys BTC summary ($0.25)         -> ALLOW
 *   3. Agent buys GPU inference ($1.00)        -> ALLOW
 *
 * Phase 3 - Policy Enforcement:
 *   4. Agent tries premium report ($5.00)      -> DENY (per-request cap)
 *   5. Agent buys market feed ($0.10)           -> ALLOW
 *   6. Agent tries more research ($0.50)        -> DENY (daily cap exceeded)
 *
 * Phase 4 - Audit Trail:
 *   Print summary of all receipts.
 */
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import { Permission } from '@bolyra/sdk';
import { setupDelegation, type WalletPolicy } from './delegation.js';
import { BaseAgentWallet, type PaymentRequest, type Receipt } from './base-wallet.js';

const API_PORT = 3301;
const API_URL = `http://localhost:${API_PORT}`;

// ── ANSI helpers ──
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const MAGENTA = '\x1b[35m';

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

function banner(text: string): void {
  const line = '='.repeat(64);
  console.log(`\n${CYAN}${line}${RESET}`);
  console.log(`  ${BOLD}${text}${RESET}`);
  console.log(`${CYAN}${line}${RESET}\n`);
}

function phaseBanner(phase: string, desc: string): void {
  console.log(`\n${MAGENTA}${BOLD}--- ${phase}: ${desc} ---${RESET}\n`);
}

interface X402Requirements {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  recipient: string;
  description: string;
}

interface ScenarioResult {
  label: string;
  receipt: Receipt;
  data?: any;
  httpStatus: number;
}

function printResult(idx: number, result: ScenarioResult): void {
  const allowed = result.receipt.decision === 'allow';
  const icon = allowed ? `${GREEN}[ALLOW]${RESET}` : `${RED}[DENY]${RESET}`;
  console.log(`  ${BOLD}Scenario ${idx}:${RESET} ${icon} ${result.label}`);
  console.log(`    ${DIM}Amount:${RESET}   $${(result.receipt.amount / 100).toFixed(2)} ${result.receipt.asset}`);
  if (result.receipt.reason) {
    console.log(`    ${DIM}Reason:${RESET}   ${YELLOW}${result.receipt.reason}${RESET}`);
  }
  console.log(`    ${DIM}Daily:${RESET}    $${(result.receipt.dailySpent / 100).toFixed(2)} spent / $${((result.receipt.dailySpent + result.receipt.dailyRemaining) / 100).toFixed(2)} cap`);
  console.log(`    ${DIM}Receipt:${RESET}  ${result.receipt.id}`);
  if (allowed && result.data?.data) {
    const preview = JSON.stringify(result.data.data).slice(0, 80);
    console.log(`    ${DIM}Data:${RESET}     ${preview}...`);
  }
  console.log('');
}

/**
 * Fetch a paid API endpoint, parse the 402 response, and evaluate
 * the payment request through the BaseAgentWallet.
 */
async function fetchAndEvaluate(
  wallet: BaseAgentWallet,
  endpoint: string,
  label: string,
): Promise<ScenarioResult> {
  const url = `${API_URL}${endpoint}`;

  // Step 1: Hit the API — expect a 402
  const res = await globalThis.fetch(url);
  const body = await res.json();

  if (res.status !== 402) {
    // Not a paid endpoint — shouldn't happen in this demo
    return {
      label,
      receipt: wallet.evaluatePayment({ url, amount: 0, asset: 'USDC', network: 'base-sepolia' }),
      data: body,
      httpStatus: res.status,
    };
  }

  // Step 2: Parse x402 requirements
  const req: X402Requirements = body.requirements;
  const amount = parseInt(req.amount, 10);

  // Step 3: Evaluate through wallet policy
  const paymentReq: PaymentRequest = {
    url,
    amount,
    asset: req.asset,
    network: req.network,
  };

  const receipt = wallet.evaluatePayment(paymentReq);

  // Step 4: If allowed, re-fetch with payment proof
  if (receipt.decision === 'allow') {
    const nonce = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const paidRes = await globalThis.fetch(url, {
      headers: {
        'X-402-Payment': JSON.stringify({
          nonce,
          agentDid: receipt.agentDid,
          amount: req.amount,
          asset: req.asset,
          network: req.network,
          recipient: req.recipient,
          txHash: `0x${Date.now().toString(16)}${nonce.slice(-6)}`,
        }),
      },
    });
    const paidData = await paidRes.json();
    return { label, receipt, data: paidData, httpStatus: paidRes.status };
  }

  return { label, receipt, data: body, httpStatus: 403 };
}

export async function runDemo(): Promise<void> {
  const procs: ChildProcess[] = [];

  try {
    banner('Base Agent Wallet Demo');
    console.log('Human-delegated, ZKP-scoped spending for AI agents on Base.\n');

    // ── Start mock API server ──
    console.log(`${DIM}Starting mock x402 API on port ${API_PORT}...${RESET}`);
    const apiProc = spawn('npx', ['tsx', path.join(import.meta.dirname ?? __dirname, 'paid-api.ts')], {
      env: { ...process.env, API_PORT: String(API_PORT) },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(apiProc);
    apiProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`${DIM}[api] ${d}${RESET}`));
    await sleep(2000);

    // ══════════════════════════════════════════════════════════
    // Phase 1: Human Delegation
    // ══════════════════════════════════════════════════════════
    phaseBanner('Phase 1', 'Human Delegation');

    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 60 min

    const delegation = await setupDelegation({
      permissions: [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
      maxPerRequest: 200,   // $2.00
      dailyCap: 200,        // $2.00
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
      expiresAt,
    });

    console.log(`  ${BOLD}Human Identity${RESET}`);
    console.log(`    Commitment: ${delegation.humanIdentity.commitment.toString(16).slice(0, 20)}...`);
    console.log('');

    console.log(`  ${BOLD}Agent Credential${RESET}`);
    console.log(`    Commitment:  ${delegation.agentCredential.commitment.toString(16).slice(0, 20)}...`);
    console.log(`    Permissions: READ_DATA, FINANCIAL_SMALL`);
    console.log('');

    console.log(`  ${BOLD}Wallet Policy${RESET}`);
    console.log(`    Agent DID:       ${delegation.walletPolicy.agentDid}`);
    console.log(`    Max per request: $${(delegation.walletPolicy.maxPerRequest / 100).toFixed(2)}`);
    console.log(`    Daily cap:       $${(delegation.walletPolicy.dailyCap / 100).toFixed(2)}`);
    console.log(`    Assets:          ${delegation.walletPolicy.allowedAssets.join(', ')}`);
    console.log(`    Networks:        ${delegation.walletPolicy.allowedNetworks.join(', ')}`);
    console.log(`    Expires:         ${delegation.walletPolicy.expiresAt}`);
    console.log('');

    // Create wallet
    const wallet = new BaseAgentWallet(delegation.walletPolicy);

    // ══════════════════════════════════════════════════════════
    // Phase 2: Agent Transacts
    // ══════════════════════════════════════════════════════════
    phaseBanner('Phase 2', 'Agent Transacts');

    const s1 = await fetchAndEvaluate(wallet, '/research/nvda', 'NVDA earnings analysis ($0.50)');
    printResult(1, s1);

    const s2 = await fetchAndEvaluate(wallet, '/research/btc', 'BTC market summary ($0.25)');
    printResult(2, s2);

    const s3 = await fetchAndEvaluate(wallet, '/compute/gpu-hour', '1h GPU inference ($1.00)');
    printResult(3, s3);

    // ══════════════════════════════════════════════════════════
    // Phase 3: Policy Enforcement
    // ══════════════════════════════════════════════════════════
    phaseBanner('Phase 3', 'Policy Enforcement');

    const s4 = await fetchAndEvaluate(wallet, '/premium/report', 'Premium sector report ($5.00)');
    printResult(4, s4);

    const s5 = await fetchAndEvaluate(wallet, '/data/market-feed', 'Real-time market feed ($0.10)');
    printResult(5, s5);

    const s6 = await fetchAndEvaluate(wallet, '/research/nvda', 'More NVDA research ($0.50)');
    printResult(6, s6);

    // ══════════════════════════════════════════════════════════
    // Phase 4: Audit Trail
    // ══════════════════════════════════════════════════════════
    phaseBanner('Phase 4', 'Audit Trail');

    const receipts = wallet.getReceipts();
    const allowed = receipts.filter(r => r.decision === 'allow');
    const denied = receipts.filter(r => r.decision === 'deny');

    console.log(`  ${BOLD}Summary${RESET}`);
    console.log(`    Total decisions: ${receipts.length}`);
    console.log(`    ${GREEN}Allowed:${RESET}  ${allowed.length}`);
    console.log(`    ${RED}Denied:${RESET}   ${denied.length}`);
    console.log(`    Total spent:     $${(wallet.getDailySpent() / 100).toFixed(2)} / $${((wallet.getDailySpent() + wallet.getDailyRemaining()) / 100).toFixed(2)} daily cap`);
    console.log('');

    console.log(`  ${BOLD}All Receipts:${RESET}`);
    for (const r of receipts) {
      const icon = r.decision === 'allow' ? `${GREEN}ALLOW${RESET}` : `${RED}DENY${RESET}`;
      const amt = `$${(r.amount / 100).toFixed(2)}`;
      console.log(`    ${r.id}  ${icon}  ${amt.padEnd(7)} ${r.url.replace(API_URL, '')}`);
    }
    console.log('');

    console.log(`${BOLD}Agent wallet = policy-enforced spender, not just a key.${RESET}`);
    console.log('Every decision has a receipt with agent DID, amount, and reason.');
    console.log('Delegation is ZKP-backed and scope-narrowed from the human.');
    console.log('');

  } finally {
    for (const p of procs) p.kill('SIGTERM');
    await sleep(500);
  }
}
