/**
 * Off-chain delegation demo.
 *
 * Shows the full v0.3 chain end-to-end without any hardhat / on-chain leg:
 *   human + rootCred  →  rootCred delegates to agentA (narrow scope)
 *                     →  agentA delegates to agentB (narrower scope)
 *
 * Then runs the verifier against the v=2 bundle and prints the resulting
 * BolyraAuthContext, including chainDepth, effective permission bitmask,
 * and the leaf delegatee that's actually allowed to call tools.
 *
 * Run with:
 *   cd examples/mcp-demo && npx ts-node src/delegation-demo.ts
 */

import {
  attachDelegatedBolyraProof,
  verifyBundle,
  type BolyraMcpConfig,
} from '@bolyra/mcp';
import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  type AgentCredential,
} from '@bolyra/sdk';
import { DEMO_SDK_CONFIG } from './shared';

// Distinct, stable demo secrets so the demo is reproducible across runs.
const ROOT_HUMAN_SECRET =
  0x0001020304050607080900010203040506070809000102030405060708090001n;
const ROOT_OP_KEY =
  0x1101020304050607080900010203040506070809000102030405060708090001n;
const AGENT_A_OP_KEY =
  0x2201020304050607080900010203040506070809000102030405060708090002n;
const AGENT_B_OP_KEY =
  0x3301020304050607080900010203040506070809000102030405060708090003n;

const ROOT_MODEL = 0xa1n;
const AGENT_A_MODEL = 0xa2n;
const AGENT_B_MODEL = 0xa3n;

const ROOT_EXPIRY = 4_102_444_800n; // 2100-01-01
const AGENT_A_EXPIRY = ROOT_EXPIRY - 3600n;
const AGENT_B_EXPIRY = AGENT_A_EXPIRY - 60n;

// Cumulative-bit scope narrowing:
//   root:    bits 0,1,2,3,4    (0b11111 = 0x1F) — read+write+financial up to UNLIMITED
//   agent A: bits 0,1,2,3      (0b01111 = 0x0F) — drop FINANCIAL_UNLIMITED
//   agent B: bits 0,1          (0b00011 = 0x03) — read+write only
const ROOT_SCOPE: Permission[] = [
  Permission.READ_DATA,
  Permission.WRITE_DATA,
  Permission.FINANCIAL_SMALL,
  Permission.FINANCIAL_MEDIUM,
  Permission.FINANCIAL_UNLIMITED,
];
const AGENT_A_SCOPE: Permission[] = [
  Permission.READ_DATA,
  Permission.WRITE_DATA,
  Permission.FINANCIAL_SMALL,
  Permission.FINANCIAL_MEDIUM,
];
const AGENT_B_SCOPE: Permission[] = [Permission.READ_DATA, Permission.WRITE_DATA];

async function main() {
  console.log('=== Bolyra v0.3 off-chain delegation demo ===\n');

  // 1. Identities + credentials.
  const human = await createHumanIdentity(ROOT_HUMAN_SECRET);
  const rootCred = await createAgentCredential(
    ROOT_MODEL,
    ROOT_OP_KEY,
    ROOT_SCOPE,
    ROOT_EXPIRY,
  );
  // agentA's credential commitment MUST match what hop 0 grants — same
  // (modelHash, operatorPubkey, scope, expiry) used in createAgentCredential.
  const agentACred = await createAgentCredential(
    AGENT_A_MODEL,
    AGENT_A_OP_KEY,
    AGENT_A_SCOPE,
    AGENT_A_EXPIRY,
  );
  const agentBCred = await createAgentCredential(
    AGENT_B_MODEL,
    AGENT_B_OP_KEY,
    AGENT_B_SCOPE,
    AGENT_B_EXPIRY,
  );

  console.log(`root cred commitment:    ${rootCred.commitment}`);
  console.log(`agent A cred commitment: ${agentACred.commitment}`);
  console.log(`agent B cred commitment: ${agentBCred.commitment}\n`);

  // 2. Build the v=2 bundle: handshake bound to root + 2 delegation hops.
  console.log('Generating handshake + 2-hop delegation chain...');
  const t0 = Date.now();
  const auth = await attachDelegatedBolyraProof(
    human,
    rootCred,
    [
      {
        delegator: rootCred,
        delegatorOperatorPrivateKey: ROOT_OP_KEY,
        delegateeCommitment: agentACred.commitment,
        delegateeScope: agentACred.permissionBitmask,
        delegateeExpiry: agentACred.expiryTimestamp,
      },
      {
        delegator: agentACred,
        delegatorOperatorPrivateKey: AGENT_A_OP_KEY,
        delegateeCommitment: agentBCred.commitment,
        delegateeScope: agentBCred.permissionBitmask,
        delegateeExpiry: agentBCred.expiryTimestamp,
      },
    ],
    DEMO_SDK_CONFIG,
  );
  const provingMs = Date.now() - t0;
  console.log(`Bundle generated in ${provingMs}ms (v=${auth.bundle.v}, chain depth ${auth.bundle.delegationChain?.length ?? 0})\n`);

  // 3. Verifier side: register the credential, run verifyBundle.
  const registry = new Map<string, AgentCredential>();
  registry.set(rootCred.commitment.toString(), rootCred);

  const verifyCfg: BolyraMcpConfig = {
    network: 'demo',
    minScore: 70,
    maxProofAge: 600,
    resolveCredential: async (commitment: string) =>
      registry.get(commitment) ?? null,
    sdkConfig: DEMO_SDK_CONFIG,
  };

  console.log('Verifying bundle off-chain...');
  const v0 = Date.now();
  const ctx = await verifyBundle(auth.bundle, verifyCfg);
  const verifyMs = Date.now() - v0;
  console.log(`Verified in ${verifyMs}ms\n`);

  console.log('--- BolyraAuthContext ---');
  console.log(`verified:            ${ctx.verified}`);
  console.log(`score:               ${ctx.score}`);
  console.log(`did:                 ${ctx.did}`);
  console.log(`chainDepth:          ${ctx.chainDepth}`);
  console.log(`effectiveCommitment: ${ctx.effectiveCommitment}`);
  console.log(`permissionBitmask:   0b${ctx.permissionBitmask.toString(2).padStart(8, '0')} (=${ctx.permissionBitmask})`);
  if (ctx.warnings.length > 0) console.log(`warnings:            ${JSON.stringify(ctx.warnings)}`);
  if (ctx.reason) console.log(`reason:              ${ctx.reason}`);

  // 4. Sanity assertions — exit non-zero if any of these fail so the demo
  //    doubles as a smoke test.
  const expectedLeafScope = agentBCred.permissionBitmask;
  const expectedLeafCommit = agentBCred.commitment.toString();
  const ok =
    ctx.verified &&
    ctx.chainDepth === 2 &&
    ctx.permissionBitmask === expectedLeafScope &&
    ctx.effectiveCommitment === expectedLeafCommit;

  console.log(`\nResult: ${ok ? 'PASS' : 'FAIL'}`);
  if (!ok) {
    console.error(`Expected chainDepth=2, leaf scope=${expectedLeafScope}, leaf commitment=${expectedLeafCommit}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
