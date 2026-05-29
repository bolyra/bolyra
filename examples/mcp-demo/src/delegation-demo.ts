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
import type { AgentCredential } from '@bolyra/sdk';
import {
  DEMO_SDK_CONFIG,
  loadDemoDelegationIdentities,
} from './shared';

async function main() {
  console.log('=== Bolyra v0.3 off-chain delegation demo ===\n');

  const {
    human,
    rootCred,
    rootOpKey,
    agentACred,
    agentAOpKey,
    agentBCred,
  } = await loadDemoDelegationIdentities();

  console.log(`root cred commitment:    ${rootCred.commitment}`);
  console.log(`agent A cred commitment: ${agentACred.commitment}`);
  console.log(`agent B cred commitment: ${agentBCred.commitment}\n`);

  console.log('Generating handshake + 2-hop delegation chain...');
  const t0 = Date.now();
  const auth = await attachDelegatedBolyraProof(
    human,
    rootCred,
    [
      {
        delegator: rootCred,
        delegatorOperatorPrivateKey: rootOpKey,
        delegateeCommitment: agentACred.commitment,
        delegateeScope: agentACred.permissionBitmask,
        delegateeExpiry: agentACred.expiryTimestamp,
      },
      {
        delegator: agentACred,
        delegatorOperatorPrivateKey: agentAOpKey,
        delegateeCommitment: agentBCred.commitment,
        delegateeScope: agentBCred.permissionBitmask,
        delegateeExpiry: agentBCred.expiryTimestamp,
      },
    ],
    DEMO_SDK_CONFIG,
  );
  const provingMs = Date.now() - t0;
  console.log(`Bundle generated in ${provingMs}ms (v=${auth.bundle.v}, chain depth ${auth.bundle.delegationChain?.length ?? 0})\n`);

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

  const ok =
    ctx.verified &&
    ctx.chainDepth === 2 &&
    ctx.permissionBitmask === agentBCred.permissionBitmask &&
    ctx.effectiveCommitment === agentBCred.commitment.toString();

  console.log(`\nResult: ${ok ? 'PASS' : 'FAIL'}`);
  if (!ok) {
    console.error(
      `Expected chainDepth=2, leaf scope=${agentBCred.permissionBitmask}, leaf commitment=${agentBCred.commitment}`,
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
