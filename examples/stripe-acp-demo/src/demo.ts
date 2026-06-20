/**
 * Bolyra x Stripe ACP Demo
 *
 * Demonstrates the full authorization flow: a human delegates FINANCIAL_SMALL
 * authority to an agent, then the agent attempts four operations. Two succeed,
 * two are correctly rejected. Every decision produces a signed audit receipt
 * that is independently verified at the end.
 *
 * No real Stripe calls. No circuit artifacts needed. Runs in < 1 second.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

import {
  createDevIdentities,
  Permission,
} from '@bolyra/sdk';

import {
  authContextToStripeACPContext,
  verifyStripeACPSpend,
} from '@bolyra/payment-protocols';
import type { BolyraVerifiedContext, StripeACPContext } from '@bolyra/payment-protocols';

import {
  createCommerceReceipt,
  signReceipt,
  verifyReceipt,
} from '@bolyra/receipts';
import type {
  CommerceReceiptInput,
  SignedReceipt,
  ReceiptSignerConfig,
} from '@bolyra/receipts';

import { bold, green, red, cyan, dim, yellow, CHECK, CROSS, header, line } from './colors';
import { simulatePaymentIntent } from './stripe-sim';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Agent bitmask: READ_DATA (0) + WRITE_DATA (1) + FINANCIAL_SMALL (2) = 0b00000111 = 7
const AGENT_BITMASK = 0b00000111n;

const RECEIPTS_DIR = path.resolve(__dirname, '../receipts');

// Ephemeral signing key for receipts (demo only — never persisted)
const SIGNER_PRIVATE_KEY = '0x' + crypto.randomBytes(32).toString('hex');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ensureReceiptsDir(): void {
  if (!fs.existsSync(RECEIPTS_DIR)) {
    fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  }
}

function writeReceipt(filename: string, receipt: SignedReceipt): string {
  const filePath = path.join(RECEIPTS_DIR, filename);
  fs.writeFileSync(filePath, JSON.stringify(receipt, null, 2));
  return filePath;
}

function buildReceiptInput(
  acpCtx: StripeACPContext,
  allowed: boolean,
  amount: number,
  currency: string,
  reasonCode?: string,
  intentId?: string,
): CommerceReceiptInput {
  // Deterministic mock proof data for receipt hashing
  const mockProof = { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'] };

  return {
    rootDid: acpCtx.rootAgentDid,
    actingDid: acpCtx.actingAgentDid,
    credentialCommitment: '0',
    effectiveCommitment: '0',
    allowed,
    ...(reasonCode !== undefined && { reasonCode }),
    score: acpCtx.score,
    permissionBitmask: acpCtx.effectiveScope,
    chainDepth: acpCtx.delegationDepth,
    humanProof: { proof: mockProof },
    agentProof: { proof: mockProof },
    humanPublicSignals: ['0'],
    agentPublicSignals: ['0'],
    bundleVersion: 2 as const,
    nonce: crypto.randomBytes(16).toString('hex'),
    commerce: {
      rail: 'stripe-acp',
      amount,
      currency,
      merchant: 'demo-merchant',
      intentHash: intentId ?? 'none',
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log();
  console.log(bold('=== Bolyra x Stripe ACP Demo ==='));
  console.log();

  // ── Setup ──────────────────────────────────────────────────────────────
  console.log(dim('Setting up identities...'));

  const { human, agent } = await createDevIdentities({
    permissionBitmask: AGENT_BITMASK,
  });

  // Build BolyraVerifiedContext directly (simulates what verifyBundle returns)
  const commitment = agent.commitment.toString();
  const commitmentHex = BigInt(commitment).toString(16).padStart(64, '0');
  const actingDid = `did:bolyra:base-sepolia:${commitmentHex}`;

  // Root DID — in a real flow the root would be different from the acting agent.
  // For this demo they share the same commitment (single-hop delegation).
  const rootDid = actingDid;

  const bolyraCtx: BolyraVerifiedContext = {
    verified: true,
    score: 95,
    did: rootDid,
    permissionBitmask: AGENT_BITMASK,
    chainDepth: 1,
    effectiveCommitment: commitment,
    warnings: [],
  };

  // Convert to Stripe ACP context
  const acpCtx = authContextToStripeACPContext(bolyraCtx);

  line('Human identity:', 'created (dev mode)');
  line('Agent credential:', `FINANCIAL_SMALL (bitmask: 0b${AGENT_BITMASK.toString(2).padStart(8, '0')})`);
  line('Delegation:', `human -> agent (1 hop)`);
  line('ACP tier:', `${acpCtx.spendingLimits.tier} (cap: $${acpCtx.spendingLimits.maxTransactionAmount / 100})`);

  // Receipt signer config
  const signerConfig: ReceiptSignerConfig = {
    issuer: 'bolyra-stripe-acp-demo',
    keyId: 'demo-ephemeral-key-1',
    privateKey: SIGNER_PRIVATE_KEY,
  };

  ensureReceiptsDir();

  const signedReceipts: { name: string; receipt: SignedReceipt }[] = [];

  // ── Scenario 1: $25 charge (ALLOWED) ──────────────────────────────────
  header('Scenario 1: $25 charge');

  const decision1 = verifyStripeACPSpend(acpCtx, 2500, 'usd', 'authorize');

  if (!decision1.allowed) {
    console.error(red('UNEXPECTED: $25 charge was rejected'));
    process.exit(1);
  }

  const pi1 = simulatePaymentIntent(2500, 'usd', acpCtx.actingAgentDid, acpCtx.rootAgentDid, '');
  const input1 = buildReceiptInput(acpCtx, true, 2500, 'usd', undefined, pi1.id);
  const payload1 = createCommerceReceipt(input1, { issuer: signerConfig.issuer, keyId: signerConfig.keyId });
  const signed1 = signReceipt(payload1, signerConfig);
  const file1 = writeReceipt('scenario-1-allowed.json', signed1);

  line('Spend check:', green('ALLOWED') + ` (tier=${decision1.tier}, cap=$${decision1.capChecked / 100})`);
  line('PaymentIntent:', `${pi1.id} ${yellow('(SIMULATED)')}`);
  line('Receipt:', cyan(path.relative(process.cwd(), file1)));
  console.log(`  ${CHECK} ${green('$25.00 authorized')}`);

  signedReceipts.push({ name: 'scenario-1-allowed.json', receipt: signed1 });

  // ── Scenario 2: $480 charge (REJECTED) ────────────────────────────────
  header('Scenario 2: $480 charge');

  const decision2 = verifyStripeACPSpend(acpCtx, 48000, 'usd', 'authorize');

  if (decision2.allowed) {
    console.error(red('UNEXPECTED: $480 charge was allowed'));
    process.exit(1);
  }

  const input2 = buildReceiptInput(acpCtx, false, 48000, 'usd', decision2.reason);
  const payload2 = createCommerceReceipt(input2, { issuer: signerConfig.issuer, keyId: signerConfig.keyId });
  const signed2 = signReceipt(payload2, signerConfig);
  const file2 = writeReceipt('scenario-2-rejected.json', signed2);

  line('Spend check:', red('REJECTED'));
  line('Reason:', decision2.reason ?? 'unknown');
  line('Receipt:', cyan(path.relative(process.cwd(), file2)));
  console.log(`  ${CROSS} ${red('$480.00 correctly rejected')}`);

  signedReceipts.push({ name: 'scenario-2-rejected.json', receipt: signed2 });

  // ── Scenario 3: Confirm without SIGN_ON_BEHALF (REJECTED) ─────────────
  header('Scenario 3: Confirm without SIGN_ON_BEHALF');

  const decision3 = verifyStripeACPSpend(acpCtx, 2500, 'usd', 'confirm');

  if (decision3.allowed) {
    console.error(red('UNEXPECTED: confirm was allowed without SIGN_ON_BEHALF'));
    process.exit(1);
  }

  const input3 = buildReceiptInput(acpCtx, false, 2500, 'usd', decision3.reason);
  const payload3 = createCommerceReceipt(input3, { issuer: signerConfig.issuer, keyId: signerConfig.keyId });
  const signed3 = signReceipt(payload3, signerConfig);
  const file3 = writeReceipt('scenario-3-rejected.json', signed3);

  line('Spend check:', red('REJECTED'));
  line('Reason:', decision3.reason ?? 'unknown');
  line('Receipt:', cyan(path.relative(process.cwd(), file3)));
  console.log(`  ${CROSS} ${red('Confirm correctly rejected (no SIGN_ON_BEHALF)')}`);

  signedReceipts.push({ name: 'scenario-3-rejected.json', receipt: signed3 });

  // ── Scenario 4: Verify all receipts ────────────────────────────────────
  header('Scenario 4: Receipt Verification');

  let verified = 0;
  for (const { name, receipt } of signedReceipts) {
    const valid = verifyReceipt(receipt);
    if (valid) {
      verified++;
      line(`${name}:`, `${green('VALID')} ${CHECK}`);
    } else {
      line(`${name}:`, `${red('INVALID')} ${CROSS}`);
    }
  }

  console.log();
  if (verified === signedReceipts.length) {
    console.log(green(`All ${verified} receipts verified. Audit trail intact.`));
  } else {
    console.error(red(`Only ${verified}/${signedReceipts.length} receipts verified.`));
    process.exit(1);
  }

  // ── Summary ────────────────────────────────────────────────────────────
  console.log();
  console.log(bold('Summary'));
  console.log(dim('─'.repeat(60)));
  console.log(`  1. charge($25)   ${CHECK} ${green('AUTHORIZED')}  — within $100 cap`);
  console.log(`  2. charge($480)  ${CROSS} ${red('REJECTED')}     — exceeds small-tier cap`);
  console.log(`  3. confirm($25)  ${CROSS} ${red('REJECTED')}     — no SIGN_ON_BEHALF (bit 5)`);
  console.log(`  4. verify(3)     ${CHECK} ${green('3/3 VALID')}    — audit trail intact`);
  console.log(dim('─'.repeat(60)));
  console.log();
  console.log(bold('All decisions are signed. All receipts are verifiable.'));
  console.log();
}

main().catch((err) => {
  console.error(red('Demo failed:'), err);
  process.exit(1);
});
