/**
 * Protected File Server — Bolyra MCP example (client side).
 *
 * Demonstrates:
 *   1. Full-permission dev identities → list_files and read_file succeed.
 *   2. Read-only dev identities       → write_file is denied by policy.
 *
 * Run:  npx tsx client.ts
 */

import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof } from '@bolyra/mcp';

const SERVER_PATH = path.resolve(__dirname, 'server.ts');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function label(msg: string): void {
  console.log('\n' + '─'.repeat(60));
  console.log(msg);
  console.log('─'.repeat(60));
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
  // Spin up the server subprocess.
  const transport = new StdioClientTransport({
    command: 'npx',
    args: ['tsx', SERVER_PATH],
    stderr: 'pipe',
  });

  const client = new Client(
    { name: 'bolyra-file-client', version: '0.0.1' },
    { capabilities: {} },
  );

  await client.connect(transport);

  // ── Step 1: full-permission identities ──────────────────────────────────
  label('Step 1: Create full-permission dev identities');
  const { human, agent } = await createDevIdentities();
  console.log('  permissionBitmask: 0b11111111 (all bits set)');

  const fullAuth = await attachBolyraProof(human, agent, { devMode: true });
  console.log('  dev-mode proof generated (no ZK circuit needed)');

  // ── Step 2: list_files ──────────────────────────────────────────────────
  label('Step 2: list_files (requires READ_DATA bit 0) — expect success');
  const listResult = await client.callTool({
    name: 'list_files',
    arguments: {},
    _meta: { bolyra: fullAuth.meta.bolyra },
  });
  printResult(listResult as any);

  // ── Step 3: read_file ───────────────────────────────────────────────────
  label('Step 3: read_file hello.txt (requires READ_DATA bit 0) — expect success');
  const readResult = await client.callTool({
    name: 'read_file',
    arguments: { name: 'hello.txt' },
    _meta: { bolyra: fullAuth.meta.bolyra },
  });
  printResult(readResult as any);

  // ── Step 4: restricted identities (READ only) ───────────────────────────
  label('Step 4: Create read-only dev identities (permissionBitmask: 0b01)');
  const { human: roHuman, agent: roAgent } = await createDevIdentities({
    permissionBitmask: 0b01n,
  });
  console.log('  permissionBitmask: 0b00000001 (READ_DATA only)');

  const readOnlyAuth = await attachBolyraProof(roHuman, roAgent, { devMode: true });
  console.log('  dev-mode proof generated');

  // ── Step 5: write_file with read-only creds ─────────────────────────────
  label('Step 5: write_file (requires WRITE_DATA bit 1) with read-only creds — expect denial');
  const writeResult = await client.callTool({
    name: 'write_file',
    arguments: { name: 'secret.txt', content: 'this should be blocked' },
    _meta: { bolyra: readOnlyAuth.meta.bolyra },
  });
  printResult(writeResult as any);

  // ── Done ─────────────────────────────────────────────────────────────────
  label('Done');
  console.log('  Bolyra proof flow demonstrated:');
  console.log('    • Authenticated reads succeeded with full-permission identity.');
  console.log('    • Write attempt blocked for read-only identity (policy denied).');

  await client.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
