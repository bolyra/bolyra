/**
 * BROKEN MCP server. No auth.
 *
 * This is what every stdio MCP filesystem server looks like today: any process
 * that can spawn it can call any tool. The trust boundary is "the host." When
 * the host is wrong (compromised config, malicious extension, prompt-injected
 * agent), the keys to ~/.ssh leave the building.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';

const server = new McpServer({ name: 'fs-broken', version: '0.1.0' });

// NOTE: using `(server as any).tool(...)` to sidestep a TS2589 inference
// recursion in MCP SDK 1.29's tool() overloads + zod 3.25. The runtime
// behavior is identical; only the compile-time generic resolution explodes.
(server as any).tool(
  'read_file',
  'Read a file from disk and return its contents.',
  { path: z.string() },
  async ({ path: filePath }: { path: string }) => {
    // Naive expansion of ~. Mirrors what real filesystem MCPs do.
    const expanded = filePath.startsWith('~')
      ? path.join(os.homedir(), filePath.slice(1))
      : filePath;
    const text = await fs.readFile(expanded, 'utf8');
    return { content: [{ type: 'text' as const, text }] };
  },
);

const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[server-broken] connect error:', err);
  process.exit(1);
});
