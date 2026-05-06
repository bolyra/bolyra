/**
 * FIXED MCP server. Same tool, same protocol, same transport. One wrapper line.
 *
 *   withBolyraAuthStdio(server, { resolveCredential, toolPolicy })
 *
 * Now `read_file` requires a valid Bolyra mutual handshake in `_meta.bolyra`
 * AND the agent's permission bitmask must include READ_DATA (bit 0).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';

import { withBolyraAuthStdio } from '@bolyra/mcp';
import { loadDemoCredentialRegistry, ensureRegistryPopulated, DEMO_SDK_CONFIG } from './shared';

const server = new McpServer({ name: 'fs-fixed', version: '0.1.0' });

// See server-broken.ts comment about the `as any` cast.
(server as any).tool(
  'read_file',
  'Read a file from disk and return its contents (Bolyra-gated).',
  { path: z.string() },
  async ({ path: filePath }: { path: string }) => {
    const expanded = filePath.startsWith('~')
      ? path.join(os.homedir(), filePath.slice(1))
      : filePath;
    const text = await fs.readFile(expanded, 'utf8');
    return { content: [{ type: 'text' as const, text }] };
  },
);

// The wrapper. After this point, every tools/call request is gated.
const registry = loadDemoCredentialRegistry();
withBolyraAuthStdio(server.server, {
  resolveCredential: async (commitment: string) => {
    await ensureRegistryPopulated(registry);
    return registry.get(commitment) ?? null;
  },
  toolPolicy: {
    // READ_DATA bit per @bolyra/sdk Permission enum.
    read_file: 0b01n,
  },
  sdkConfig: DEMO_SDK_CONFIG,
});

const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[server-fixed] connect error:', err);
  process.exit(1);
});
