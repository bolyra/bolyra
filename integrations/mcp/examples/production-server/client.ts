/**
 * Production-shaped MCP Client — Bolyra example.
 *
 * Spawns server.ts and demonstrates:
 *   1. Full-permission agent calls list_files  -> success
 *   2. Full-permission agent calls read_file   -> success
 *   3. Read-only agent calls write_file        -> policy denied
 *
 * Modes:
 *   npx tsx client.ts --dev         Mock proofs (instant)
 *   npx tsx client.ts --production  Real ZKP proofs (needs BOLYRA_CIRCUIT_DIR)
 */

import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof } from '@bolyra/mcp';
import { parseMode, sdkConfigForMode } from './mode';

const SERVER_PATH = path.resolve(__dirname, 'server.ts');
const mode = parseMode();
const sdkConfig = sdkConfigForMode(mode);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function label(msg: string): void {
  console.log('\n' + '-'.repeat(60));
  console.log(msg);
  console.log('-'.repeat(60));
}

function printResult(result: { isError?: boolean; content?: Array<{ type: string; text: string }> }): void {
  const text = (result.content ?? [])[0]?.text ?? '(no content)';
  if (result.isError) {
    console.log('  ERROR:', text);
  } else {
    console.log('  OK:', text);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log(`Mode: ${mode}`);

  // Pass the mode flag through to the server subprocess.
  const modeFlag = mode === 'production' ? '--production' : '--dev';
  const transport = new StdioClientTransport({
    command: 'npx',
    args: ['tsx', SERVER_PATH, modeFlag],
    stderr: 'pipe',
    env: { ...process.env },
  });

  const client = new Client(
    { name: 'bolyra-production-client', version: '0.0.1' },
    { capabilities: {} },
  );

  await client.connect(transport);

  // -- Full-permission identities ------------------------------------------
  label('Step 1: Create full-permission identities');
  const { human, agent } = await createDevIdentities();
  console.log('  permissionBitmask: 0b11111111 (all bits set)');

  const proofOpts = mode === 'dev'
    ? { devMode: true as const }
    : { sdkConfig };

  // -- list_files ----------------------------------------------------------
  // Generate a fresh proof for each call: in production mode the NonceStore
  // rejects a reused nonce, so one proof bundle cannot cover multiple calls.
  label('Step 2: list_files (requires READ_DATA bit 0) -- expect success');
  const auth1 = await attachBolyraProof(human, agent, proofOpts);
  console.log(`  proof generated (${mode} mode)`);
  const listResult = await client.callTool({
    name: 'list_files',
    arguments: {},
    _meta: { bolyra: auth1.meta.bolyra },
  });
  printResult(listResult as any);

  // -- read_file -----------------------------------------------------------
  label('Step 3: read_file hello.txt (requires READ_DATA bit 0) -- expect success');
  const auth2 = await attachBolyraProof(human, agent, proofOpts);
  console.log(`  proof generated (${mode} mode)`);
  const readResult = await client.callTool({
    name: 'read_file',
    arguments: { name: 'hello.txt' },
    _meta: { bolyra: auth2.meta.bolyra },
  });
  printResult(readResult as any);

  // -- Read-only identities ------------------------------------------------
  label('Step 4: Create read-only identities (permissionBitmask: 0b01)');
  const { human: roHuman, agent: roAgent } = await createDevIdentities({
    permissionBitmask: 0b01n,
  });
  console.log('  permissionBitmask: 0b00000001 (READ_DATA only)');

  const auth3 = await attachBolyraProof(roHuman, roAgent, proofOpts);
  console.log(`  proof generated (${mode} mode)`);

  // -- write_file with read-only creds -------------------------------------
  label('Step 5: write_file (requires WRITE_DATA bit 1) with read-only creds -- expect denial');
  const writeResult = await client.callTool({
    name: 'write_file',
    arguments: { name: 'secret.txt', content: 'this should be blocked' },
    _meta: { bolyra: auth3.meta.bolyra },
  });
  printResult(writeResult as any);

  // -- Summary -------------------------------------------------------------
  label('Done');
  console.log('  Results:');
  console.log('    list_files  with full perms  -> OK');
  console.log('    read_file   with full perms  -> OK');
  console.log('    write_file  with read-only   -> DENIED (policy)');

  await client.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
