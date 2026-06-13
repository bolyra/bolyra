#!/usr/bin/env npx tsx
/**
 * Production-shaped MCP Server — Bolyra example.
 *
 * Same 3-tool sandbox as protected-file-server, but configured with
 * production-grade auth: credential lookup, nonce replay protection,
 * root validation, and per-tool permission policy.
 *
 * Modes:
 *   --dev         Mock proof verification (instant, no circuits)
 *   --production  Real ZKP verification (requires BOLYRA_CIRCUIT_DIR)
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { withBolyraAuthStdio } from '../../src/server-stdio';
import { MemoryNonceStore } from '../../src/nonce-store';
import { parseMode, sdkConfigForMode } from './mode';
import { InMemoryCredentialStore } from './credential-store';
import { createMockRootValidator } from './root-validator';
import { loadExampleIdentities } from './example-identities';

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

const mode = parseMode();
const sdkConfig = sdkConfigForMode(mode);

// ---------------------------------------------------------------------------
// Sandbox setup
// ---------------------------------------------------------------------------

const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-prod-'));
fs.writeFileSync(
  path.join(SANDBOX, 'hello.txt'),
  'Hello from the Bolyra production-shaped file server!\n',
);

function sandboxPath(name: string): string {
  const resolved = path.resolve(SANDBOX, name);
  if (!resolved.startsWith(SANDBOX + path.sep) && resolved !== SANDBOX) {
    throw new Error(`path traversal rejected: ${name}`);
  }
  return resolved;
}

// ---------------------------------------------------------------------------
// MCP server + tools
// ---------------------------------------------------------------------------

const mcpServer = new McpServer(
  { name: 'bolyra-production-server-example', version: '0.0.1' },
  { capabilities: { tools: {} } },
);

mcpServer.tool('list_files', 'List files in the sandbox', {}, async () => {
  const names = fs.readdirSync(SANDBOX);
  return { content: [{ type: 'text' as const, text: names.join('\n') || '(empty)' }] };
});

mcpServer.tool(
  'read_file',
  'Read a sandbox file by name',
  { name: z.string().describe('Filename inside the sandbox') },
  async ({ name }) => {
    const filePath = sandboxPath(name);
    if (!fs.existsSync(filePath)) {
      return { isError: true, content: [{ type: 'text' as const, text: `not found: ${name}` }] };
    }
    return { content: [{ type: 'text' as const, text: fs.readFileSync(filePath, 'utf8') }] };
  },
);

mcpServer.tool(
  'write_file',
  'Write content to a sandbox file (requires WRITE_DATA)',
  {
    name: z.string().describe('Filename to write'),
    content: z.string().describe('UTF-8 content'),
  },
  async ({ name, content }) => {
    fs.writeFileSync(sandboxPath(name), content, 'utf8');
    return { content: [{ type: 'text' as const, text: `wrote ${content.length} bytes to ${name}` }] };
  },
);

// ---------------------------------------------------------------------------
// Bolyra auth — production-shaped config
// ---------------------------------------------------------------------------

async function start(): Promise<void> {
  const { agent, readOnlyAgent } = await loadExampleIdentities();
  const credentialStore = new InMemoryCredentialStore([agent, readOnlyAgent]);

  withBolyraAuthStdio(mcpServer.server, {
    devMode: mode === 'dev',
    resolveCredential: (commitment) => credentialStore.resolve(commitment),
    validateRoots: createMockRootValidator(),
    nonceStore: new MemoryNonceStore(),
    toolPolicy: {
      list_files: 1n,
      read_file: 1n,
      write_file: 2n,
    },
    ...(sdkConfig ? { sdkConfig } : {}),
  });

  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

start().catch((err) => {
  process.stderr.write(`[production-server] fatal: ${err}\n`);
  process.exit(1);
});
