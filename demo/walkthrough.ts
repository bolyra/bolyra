/**
 * Bolyra Prospect Walkthrough
 *
 * A single script demonstrating the full Bolyra identity flow:
 *   1. Identity creation (human + agent, dev mode)
 *   2. MCP authentication (proof bundle + verification)
 *   3. Tool policy enforcement (allowed vs denied)
 *   4. Signed receipts (secp256k1, EVM-compatible)
 *   5. Commerce authorization (Stripe ACP spend caps)
 *
 * Run: cd demo && npm install && npm start
 */

import { createDevIdentities, Permission } from '@bolyra/sdk';
import {
  attachBolyraProof,
  verifyBundle,
  checkToolPolicy,
  MemoryNonceStore,
} from '@bolyra/mcp';
import type { BolyraMcpConfig } from '@bolyra/mcp';
import { createAuthReceipt, signReceipt, verifyReceipt } from '@bolyra/receipts';
import type { ReceiptSignerConfig } from '@bolyra/receipts';
import { authorizeCommerceIntent } from '@bolyra/payment-protocols';
import type {
  StripeACPSpendDecision,
  StripeACPContext,
} from '@bolyra/payment-protocols';

// -- Colors ------------------------------------------------------------------
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

const ok = (msg: string) => console.log(`  ${GREEN}[OK]${RESET} ${msg}`);
const deny = (msg: string) => console.log(`  ${RED}[DENIED]${RESET} ${msg}`);
const info = (msg: string) => console.log(`  ${DIM}${msg}${RESET}`);
const heading = (n: number, title: string) =>
  console.log(`\n${BOLD}${CYAN}--- Stage ${n}: ${title} ---${RESET}\n`);

// -- Demo receipt signer (fixed dev key, NEVER use in production) ------------
const RECEIPT_SIGNER: ReceiptSignerConfig = {
  issuer: 'bolyra-demo',
  keyId: 'demo-key-1',
  privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
};

// ============================================================================
async function main() {
  console.log(`\n${BOLD}Bolyra Prospect Walkthrough${RESET}`);
  console.log(`${DIM}Dev mode -- no circuit artifacts, no blockchain${RESET}\n`);

  // ==========================================================================
  // Stage 1: Create Identities
  // ==========================================================================
  heading(1, 'Create Identities');

  // Full-permission agent (READ + WRITE + FINANCIAL_SMALL)
  const { human, agent } = await createDevIdentities({
    permissionBitmask: 0b00000111n, // READ_DATA | WRITE_DATA | FINANCIAL_SMALL
  });
  ok(`Human identity  (commitment: 0x${agent.commitment.toString(16).slice(0, 12)}...)`);
  ok(`Agent credential (model hash: 0x${agent.modelHash.toString(16).slice(0, 8)}..., ` +
    `permissions: READ + WRITE + FINANCIAL_SMALL)`);

  // Restricted agent (READ only)
  const { agent: restrictedAgent } = await createDevIdentities({
    permissionBitmask: 0b00000001n, // READ_DATA only
  });
  ok(`Restricted agent (permissions: READ only)`);

  // ==========================================================================
  // Stage 2: MCP Authentication
  // ==========================================================================
  heading(2, 'MCP Authentication');

  const t0 = performance.now();
  const auth = await attachBolyraProof(human, agent, { devMode: true });
  const proofMs = (performance.now() - t0).toFixed(1);

  const mcpConfig: BolyraMcpConfig = {
    devMode: true,
    nonceStore: new MemoryNonceStore(),
    toolPolicy: {
      list_files: { requireBitmask: 0b01n },   // requires READ
      write_file: { requireBitmask: 0b11n },   // requires READ + WRITE
    },
  };

  const ctx = await verifyBundle(auth.bundle, mcpConfig);
  ok(`Proof bundle generated (dev mode, ${proofMs}ms)`);
  ok(`Verification => ${ctx.verified ? 'ALLOWED' : 'DENIED'} (score: ${ctx.score}, DID: ${ctx.did.slice(0, 32)}...)`);

  // ==========================================================================
  // Stage 3: Tool Policy Enforcement
  // ==========================================================================
  heading(3, 'Tool Policy Enforcement');

  // Full agent: list_files (requires READ) -- should pass
  const listDecision = checkToolPolicy('list_files', ctx, mcpConfig);
  if (listDecision.allowed) {
    ok(`list_files (requires READ) => ALLOWED`);
  } else {
    deny(`list_files => ${listDecision.reason}`);
  }

  // Restricted agent: write_file (requires READ+WRITE) -- should be denied
  const restrictedAuth = await attachBolyraProof(human, restrictedAgent, { devMode: true });
  const restrictedCtx = await verifyBundle(restrictedAuth.bundle, mcpConfig);
  const writeDecision = checkToolPolicy('write_file', restrictedCtx, mcpConfig);
  if (writeDecision.allowed) {
    ok(`write_file with restricted agent => ALLOWED`);
  } else {
    deny(`write_file with restricted agent => insufficient permissions`);
    info(`Reason: ${writeDecision.reason}`);
  }

  // ==========================================================================
  // Stage 4: Signed Receipt
  // ==========================================================================
  heading(4, 'Signed Receipt');

  const receiptPayload = createAuthReceipt(
    {
      rootDid: ctx.did,
      actingDid: ctx.did,
      credentialCommitment: auth.bundle.credentialCommitment,
      effectiveCommitment: ctx.effectiveCommitment,
      allowed: ctx.verified,
      score: ctx.score,
      permissionBitmask: ctx.permissionBitmask.toString(),
      chainDepth: ctx.chainDepth,
      humanProof: auth.bundle.humanProof,
      agentProof: auth.bundle.agentProof,
      humanPublicSignals: auth.bundle.humanProof.publicSignals,
      agentPublicSignals: auth.bundle.agentProof.publicSignals,
      bundleVersion: auth.bundle.v,
      nonce: auth.bundle.nonce,
    },
    { issuer: RECEIPT_SIGNER.issuer, keyId: RECEIPT_SIGNER.keyId },
  );

  const signed = signReceipt(receiptPayload, RECEIPT_SIGNER);
  ok(`Receipt signed (secp256k1, EVM-compatible)`);
  info(`Receipt ID: ${signed.id}`);
  info(`Signer:     ${signed.signature.signer}`);

  const valid = verifyReceipt(signed);
  ok(`Verify receipt => ${valid ? 'VALID' : 'INVALID'}`);

  // ==========================================================================
  // Stage 5: Commerce Authorization
  // ==========================================================================
  heading(5, 'Commerce Authorization');

  // $50 payment -- under FINANCIAL_SMALL cap ($100)
  const smallSpendDecision: StripeACPSpendDecision = {
    allowed: true,
    capChecked: 10000, // $100 in cents
    tier: 'small',
  };
  const acpContext: StripeACPContext = {
    actingAgentDid: ctx.did,
    rootAgentDid: ctx.did,
    delegationDepth: 0,
    spendingLimits: {
      maxTransactionAmount: 10000,
      currency: 'USD',
      financialSmall: true,
      financialMedium: false,
      financialUnlimited: false,
      signOnBehalf: false,
      tier: 'small',
    },
    effectiveScope: ctx.permissionBitmask.toString(),
    verified: true,
    score: ctx.score,
    warnings: [],
  };

  const allowedPayment = authorizeCommerceIntent({
    intent: { rail: 'stripe-acp', amount: 5000, currency: 'USD', merchant: 'acme-widgets' },
    spendDecision: smallSpendDecision,
    acpContext,
  });
  if (allowedPayment.allowed) {
    ok(`$50 Stripe ACP payment => ALLOWED (grade: ${allowedPayment.grade})`);
  } else {
    deny(`$50 payment => ${allowedPayment.reason}`);
  }

  // $200 payment -- exceeds FINANCIAL_SMALL cap
  const overCapDecision: StripeACPSpendDecision = {
    allowed: false,
    reason: 'Amount 20000 exceeds FINANCIAL_SMALL cap of 10000',
    capChecked: 10000,
    tier: 'small',
  };

  const deniedPayment = authorizeCommerceIntent({
    intent: { rail: 'stripe-acp', amount: 20000, currency: 'USD', merchant: 'luxury-goods' },
    spendDecision: overCapDecision,
    acpContext,
  });
  if (deniedPayment.allowed) {
    ok(`$200 payment => ALLOWED`);
  } else {
    deny(`$200 payment => exceeds FINANCIAL_SMALL cap`);
    info(`Reason: ${deniedPayment.reason}`);
  }

  // -- Done ------------------------------------------------------------------
  console.log(`\n${BOLD}${GREEN}All 5 stages complete.${RESET}\n`);
}

main().catch((err) => {
  console.error(`${RED}Fatal:${RESET}`, err);
  process.exit(1);
});
