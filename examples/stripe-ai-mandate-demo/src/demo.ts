/**
 * Bolyra x Stripe agent-toolkit demo — verified agent spend.
 *
 * Cast:
 *   OPERATOR  issues a FINANCIAL_SMALL (< $100) spend mandate to an agent by
 *             signing a Bolyra request binding (`issueMandate`, @bolyra/mpp).
 *   AGENT     uses a Stripe agent-toolkit STYLE spend tool (a clearly-labeled
 *             mock of `@stripe/agent-toolkit`'s create-PaymentIntent tool).
 *   GUARD     wraps that tool so the mandate is verified BEFORE the spend:
 *             `verifyClassical` (@bolyra/mpp) checks the operator signature,
 *             then `verifyStripeACPSpend` (@bolyra/payment-protocols)
 *             enforces the Stripe ACP per-transaction cap. Every decision is
 *             signed into a hash-chained receipt.
 *
 * The authorization path is REAL shipped Bolyra code. Only the Stripe call
 * is mocked — no network, no API keys, no money moves.
 *
 * Run: npm install && npm run demo
 */

import * as fs from 'fs';
import * as path from 'path';

import { derivePublicKey } from '@bolyra/sdk';
import { createGateReceiptSigner, issueMandate } from '@bolyra/mpp';
import { verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';

import { bold, green, red, cyan, dim, yellow, CHECK, CROSS, header, line } from './colors';
import { guardSpendTool } from './guard';
import { createStripeSpendToolStub } from './stripe-toolkit-stub';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OPERATOR_PRIVATE_KEY = 42n; // demo only — never a real key
const AGENT_NAME = 'shopper-bot';
const AUDIENCE = 'acct_demo_merchant';
const MODEL = 'opus-4.1';

const RECEIPTS_DIR = path.resolve(__dirname, '../receipts');

function writeReceipt(filename: string, receipt: SignedReceipt): string {
  if (!fs.existsSync(RECEIPTS_DIR)) {
    fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  }
  const filePath = path.join(RECEIPTS_DIR, filename);
  fs.writeFileSync(filePath, JSON.stringify(receipt, null, 2));
  return filePath;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log();
  console.log(bold('=== Bolyra x Stripe agent-toolkit: verified agent spend ==='));
  console.log(dim("Stripe's toolkit lets the agent spend; Bolyra proves it was authorized to."));

  // ── Step 1: OPERATOR issues a spend mandate ────────────────────────────
  header('Step 1: Operator issues a spend mandate');

  const operatorPub = await derivePublicKey(OPERATOR_PRIVATE_KEY);
  const mandate = await issueMandate({
    operatorPrivateKey: OPERATOR_PRIVATE_KEY,
    agentName: AGENT_NAME,
    audience: AUDIENCE,
    model: MODEL,
    tier: 'small', // < $100 per transaction — nothing more
    expiry: Math.floor(Date.now() / 1000) + 3600, // 1 hour
  });

  line('Issuer:', 'operator (EdDSA-Poseidon signed binding)');
  line('Agent:', AGENT_NAME);
  line('Audience:', AUDIENCE);
  line('Tier:', `${mandate.tier} — capabilities: ${mandate.capabilities.join(', ')}`);
  line('Expiry:', new Date(mandate.expiry * 1000).toISOString());
  console.log(`  ${CHECK} mandate signed — the agent may spend < $100 per transaction`);

  // ── Step 2: wire the guard in front of the (mock) Stripe tool ─────────
  header('Step 2: Guard the Stripe spend tool');

  const stripeTool = createStripeSpendToolStub();
  const receiptSigner = createGateReceiptSigner({ issuer: 'stripe-ai-mandate-demo' });
  const guardedTool = guardSpendTool(stripeTool, {
    mandate: mandate.presentation,
    trustedOperators: [{ x: operatorPub.x.toString(), y: operatorPub.y.toString() }],
    agentName: AGENT_NAME,
    audience: AUDIENCE,
    model: MODEL,
    receiptSigner,
    merchant: AUDIENCE,
  });

  line('Stripe tool:', `${stripeTool.name} ${yellow('(MOCK — no real Stripe call)')}`);
  line('Guard:', 'verifyClassical (mandate) -> verifyStripeACPSpend (cap) -> receipt');

  const receipts: { name: string; receipt: SignedReceipt }[] = [];

  // ── Step 3: $25 spend — ALLOWED ────────────────────────────────────────
  header('Step 3: Agent attempts a $25.00 spend');

  const allowed = await guardedTool.execute({ amount: 2500, currency: 'usd' });
  if (!allowed.authorized) {
    console.error(red(`UNEXPECTED: $25 spend was denied — ${allowed.reason}`));
    process.exit(1);
  }

  line('Mandate check:', green('PASS') + dim(' — operator signature verifies; small tier covers $25'));
  line('ACP cap check:', green('PASS') + dim(` — $25.00 < $${allowed.capChecked / 100} (${allowed.tier}-tier cap)`));
  line('PaymentIntent:', `${allowed.paymentIntent.id} ${yellow('(SIMULATED)')}`);
  const allowedFile = writeReceipt('spend-25usd-allowed.json', allowed.receipt);
  line('Receipt:', cyan(path.relative(process.cwd(), allowedFile)));
  console.log(`  ${CHECK} ${green('$25.00 authorized')} — within the mandate`);
  receipts.push({ name: 'spend-25usd-allowed.json', receipt: allowed.receipt });

  // ── Step 4: $500 spend — DENIED before the Stripe call ─────────────────
  header('Step 4: Agent attempts a $500.00 spend');

  const denied = await guardedTool.execute({ amount: 50_000, currency: 'usd' });
  if (denied.authorized) {
    console.error(red('UNEXPECTED: $500 spend was authorized'));
    process.exit(1);
  }

  line('Mandate check:', red('DENY') + dim(' — $500 requires the medium tier; the mandate only signs small'));
  line('Denied by:', `${denied.deniedBy} (${denied.reason})`);
  line('Stripe called:', `${stripeTool.calls.length === 1 ? 'no' : 'YES (bug!)'} — call count still ${stripeTool.calls.length}`);
  const deniedFile = writeReceipt('spend-500usd-denied.json', denied.receipt);
  line('Receipt:', cyan(path.relative(process.cwd(), deniedFile)));
  console.log(`  ${CROSS} ${red('$500.00 denied')} — before any Stripe call`);
  receipts.push({ name: 'spend-500usd-denied.json', receipt: denied.receipt });

  if (stripeTool.calls.length !== 1) {
    console.error(red('UNEXPECTED: the mock Stripe tool ran on a denied spend'));
    process.exit(1);
  }

  // ── Step 5: verify the receipts ────────────────────────────────────────
  header('Step 5: Verify the authorization receipts');

  let verified = 0;
  for (const { name, receipt } of receipts) {
    const valid = verifyReceipt(receipt);
    if (valid) {
      verified++;
      line(`${name}:`, `${green('VALID')} ${CHECK} ${dim(`(seq ${receipt.payload.chain?.seq}, signer ${receipt.signature.signer.slice(0, 10)}...)`)}`);
    } else {
      line(`${name}:`, `${red('INVALID')} ${CROSS}`);
    }
  }
  if (verified !== receipts.length) {
    console.error(red(`Only ${verified}/${receipts.length} receipts verified.`));
    process.exit(1);
  }
  console.log(`  ${CHECK} ${green(`${verified}/${receipts.length} receipts verified — hash-chained audit trail intact`)}`);

  // ── Summary ────────────────────────────────────────────────────────────
  console.log();
  console.log(bold('Summary'));
  console.log(dim('─'.repeat(64)));
  console.log(`  1. issueMandate(small)   ${CHECK} ${green('SIGNED')}      — operator delegates < $100`);
  console.log(`  2. spend($25)            ${CHECK} ${green('AUTHORIZED')}  — mandate + ACP cap pass`);
  console.log(`  3. spend($500)           ${CROSS} ${red('DENIED')}      — before the Stripe call`);
  console.log(`  4. verify(receipts)      ${CHECK} ${green('2/2 VALID')}   — signed allow AND deny`);
  console.log(dim('─'.repeat(64)));
  console.log();
  console.log(bold("Stripe's toolkit lets the agent spend; Bolyra proves it was authorized to."));
  console.log(dim('(Real Bolyra authorization; the Stripe PaymentIntent call is a labeled mock.)'));
  console.log();
}

main().catch((err) => {
  console.error(red('Demo failed:'), err);
  process.exit(1);
});
