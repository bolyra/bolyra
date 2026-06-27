/**
 * Autonomous Agent Identity Demo
 *
 * Shows the full lifecycle of an autonomous agent with Bolyra identity:
 *
 * Phase 1: PROVISION — Human creates agent, issues credential with policy
 * Phase 2: OPERATE  — Agent autonomously calls paid APIs through gateway
 * Phase 3: AUDIT    — Receipts reviewed, policy violations caught
 * Phase 4: REVOKE   — Credential expires, agent blocked
 *
 * Designed for the Theseus Network integration conversation:
 * "Theseus agents can own money. Bolyra proves what they're allowed to do with it."
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  generateAgentKeypair, deriveAgentDid, issueCredential,
  formatPermissions, PERMISSIONS, AgentCredential,
} from './agent-identity';
import { PolicyGateway, GatewayReceipt } from './policy-gateway';

function banner(text: string): void {
  const line = '═'.repeat(68);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function printReceipt(label: string, r: GatewayReceipt): void {
  const icon = r.decision === 'allow' ? '✅' : '🚫';
  console.log(`${icon} ${label}`);
  console.log(`   Decision:   ${r.decision.toUpperCase()}`);
  console.log(`   Action:     ${r.action}`);
  if (r.amount !== undefined) {
    console.log(`   Amount:     $${(r.amount / 100).toFixed(2)} ${r.asset ?? ''}`);
  }
  console.log(`   Permission: ${r.permissionRequired} → ${r.permissionGranted ? 'GRANTED' : 'DENIED'}`);
  if (r.reason) {
    console.log(`   Reason:     ${r.reason}`);
  }
  console.log(`   Daily:      $${(r.dailySpent / 100).toFixed(2)} spent, $${(r.dailyRemaining / 100).toFixed(2)} remaining`);
  console.log(`   Receipt:    ${r.id}`);
  console.log(`   Nonce:      ${r.nonce}`);
  console.log('');
}

async function main(): Promise<void> {
  // ═══════════════════════════════════════════════════════════════════
  // PHASE 1: PROVISION — Human creates agent with scoped credential
  // ═══════════════════════════════════════════════════════════════════
  banner('PHASE 1: PROVISION — Agent Identity Creation');

  // Agent generates its own keypair (like a Theseus agent owning its keys)
  const agentKeys = generateAgentKeypair();
  const agentDid = deriveAgentDid(agentKeys.publicKey);

  console.log('Agent generated its own keypair:');
  console.log(`  Public Key:  0x${agentKeys.publicKey}`);
  console.log(`  Agent DID:   ${agentDid}`);
  console.log('');

  // Human/org issues a Bolyra credential to this agent
  const humanDid = 'did:bolyra:base-sepolia:0xHuman_Operator_Corp';
  const credential = issueCredential({
    agentKeypair: agentKeys,
    permissions: ['READ_DATA', 'WRITE_DATA', 'FINANCIAL_SMALL'],
    maxPerRequest: 200,     // $2.00
    dailyCap: 500,          // $5.00
    allowedAssets: ['USDC'],
    allowedNetworks: ['base-sepolia'],
    expiresInHours: 24,
    issuerDid: humanDid,
  });

  console.log('Human issued Bolyra credential:');
  console.log(`  Issuer:      ${credential.issuer}`);
  console.log(`  Permissions: ${formatPermissions(credential.permissionBitmask).join(', ')}`);
  console.log(`  Bitmask:     0x${credential.permissionBitmask.toString(16).padStart(2, '0')}`);
  console.log(`  Max/request: $${(credential.maxPerRequest / 100).toFixed(2)}`);
  console.log(`  Daily cap:   $${(credential.dailyCap / 100).toFixed(2)}`);
  console.log(`  Assets:      ${credential.allowedAssets.join(', ')}`);
  console.log(`  Networks:    ${credential.allowedNetworks.join(', ')}`);
  console.log(`  Expires:     ${credential.expiresAt}`);
  console.log(`  Signature:   ${credential.signature.slice(0, 16)}...`);
  console.log('');
  console.log('The agent now has a cryptographic credential proving:');
  console.log('  "I am authorized by this human to spend up to $2/request,');
  console.log('   $5/day, on USDC, on Base Sepolia, for financial-small actions."');

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 2: OPERATE — Agent autonomously calls paid APIs
  // ═══════════════════════════════════════════════════════════════════
  banner('PHASE 2: OPERATE — Autonomous Agent Actions');

  const gateway = new PolicyGateway();

  // Scenario 1: Agent reads market data ($0.25) — READ_DATA
  console.log('─── Scenario 1: Read market data ($0.25) ───');
  const s1 = gateway.evaluate(credential, 'market_data/read', 'READ_DATA', 25, 'USDC', 'base-sepolia');
  printReceipt('Read market data', s1.receipt);

  // Scenario 2: Agent buys research report ($1.50) — FINANCIAL_SMALL
  console.log('─── Scenario 2: Buy research report ($1.50) ───');
  const s2 = gateway.evaluate(credential, 'research/buy_report', 'FINANCIAL_SMALL', 150, 'USDC', 'base-sepolia');
  printReceipt('Buy research report', s2.receipt);

  // Scenario 3: Agent tries GPU inference ($1.00) — FINANCIAL_SMALL
  console.log('─── Scenario 3: Buy GPU inference ($1.00) ───');
  const s3 = gateway.evaluate(credential, 'compute/gpu_hour', 'FINANCIAL_SMALL', 100, 'USDC', 'base-sepolia');
  printReceipt('GPU inference', s3.receipt);

  // Scenario 4: Agent tries $3.00 premium data — OVER PER-REQUEST CAP
  console.log('─── Scenario 4: Premium data ($3.00) — per-request cap ───');
  const s4 = gateway.evaluate(credential, 'data/premium_feed', 'FINANCIAL_SMALL', 300, 'USDC', 'base-sepolia');
  printReceipt('Premium data → BLOCKED', s4.receipt);

  // Scenario 5: Agent tries medium financial action — MISSING PERMISSION
  console.log('─── Scenario 5: Wire transfer ($50) — wrong permission ───');
  const s5 = gateway.evaluate(credential, 'banking/wire_transfer', 'FINANCIAL_MEDIUM', 5000, 'USDC', 'base-sepolia');
  printReceipt('Wire transfer → BLOCKED', s5.receipt);

  // Scenario 6: Agent reads more data ($0.50) — under daily cap
  console.log('─── Scenario 6: Read analytics ($0.50) ───');
  const s6 = gateway.evaluate(credential, 'analytics/read', 'READ_DATA', 50, 'USDC', 'base-sepolia');
  printReceipt('Read analytics', s6.receipt);

  // Scenario 7: Agent tries another purchase ($2.00) — OVER DAILY CAP
  console.log('─── Scenario 7: Another purchase ($2.00) — daily cap ───');
  const s7 = gateway.evaluate(credential, 'research/buy_dataset', 'FINANCIAL_SMALL', 200, 'USDC', 'base-sepolia');
  printReceipt('Buy dataset → BLOCKED', s7.receipt);

  // Scenario 8: Agent tries wrong network
  console.log('─── Scenario 8: Pay on Ethereum mainnet — wrong network ───');
  const s8 = gateway.evaluate(credential, 'service/pay', 'FINANCIAL_SMALL', 50, 'USDC', 'ethereum');
  printReceipt('Ethereum payment → BLOCKED', s8.receipt);

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 3: AUDIT — Review all receipts
  // ═══════════════════════════════════════════════════════════════════
  banner('PHASE 3: AUDIT — Receipt Trail');

  const receipts = gateway.getReceipts();
  const allowed = receipts.filter(r => r.decision === 'allow');
  const denied = receipts.filter(r => r.decision === 'deny');

  console.log('Receipt Summary:');
  console.log(`  Total:    ${receipts.length}`);
  console.log(`  Allowed:  ${allowed.length}`);
  console.log(`  Denied:   ${denied.length}`);
  console.log('');

  console.log('Allowed actions:');
  for (const r of allowed) {
    console.log(`  ✅ ${r.action} — $${((r.amount ?? 0) / 100).toFixed(2)} — ${r.id}`);
  }
  console.log('');

  console.log('Denied actions (with reasons):');
  for (const r of denied) {
    console.log(`  🚫 ${r.action} — ${r.reason} — ${r.id}`);
  }
  console.log('');

  // Save receipts to disk for replay/verification
  const receiptsDir = path.join(__dirname, '..', 'receipts');
  fs.mkdirSync(receiptsDir, { recursive: true });
  const receiptsFile = path.join(receiptsDir, `${agentDid.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
  fs.writeFileSync(receiptsFile, JSON.stringify(receipts, null, 2));
  console.log(`Receipts saved to: ${receiptsFile}`);
  console.log('Replay with: bolyra replay --receipts <file>');

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 4: REVOKE — Show expired credential behavior
  // ═══════════════════════════════════════════════════════════════════
  banner('PHASE 4: REVOKE — Expired Credential');

  // Create an already-expired credential
  const expiredCred: AgentCredential = {
    ...credential,
    expiresAt: new Date(Date.now() - 3600_000).toISOString(), // expired 1h ago
  };
  // Re-sign with the expired time so signature is valid for the expired credential
  const crypto2 = await import('crypto');
  const credentialData = `${expiredCred.agentDid}|${expiredCred.permissionBitmask}|${expiredCred.maxPerRequest}|${expiredCred.dailyCap}|${expiredCred.expiresAt}`;
  expiredCred.signature = crypto2.createHmac('sha256', 'issuer-secret')
    .update(credentialData).digest('hex');

  console.log('Agent tries to act with expired credential:');
  const s9 = gateway.evaluate(expiredCred, 'market_data/read', 'READ_DATA', 25, 'USDC', 'base-sepolia');
  printReceipt('Expired agent → BLOCKED', s9.receipt);

  // ═══════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════
  banner('Demo Complete');

  console.log('Full lifecycle demonstrated:');
  console.log('');
  console.log('  1. PROVISION  Agent generates keypair, human issues credential');
  console.log('                with permissions, spend limits, and expiry.');
  console.log('');
  console.log('  2. OPERATE    Agent autonomously calls paid APIs. Gateway');
  console.log('                checks credential, permissions, spend caps,');
  console.log('                replay protection at every request.');
  console.log('');
  console.log('  3. AUDIT      Every decision (allow + deny) has a signed');
  console.log('                receipt with agent DID, amount, and reason.');
  console.log('                Receipts saved to disk for replay.');
  console.log('');
  console.log('  4. REVOKE     Expired credentials are rejected. Human');
  console.log('                controls the lifecycle.');
  console.log('');
  console.log('Agents own keys and hold balances.');
  console.log('Bolyra proves what they\'re allowed to do with them.');
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exit(1);
});
