#!/usr/bin/env npx tsx
/**
 * Minimal MCP server harness for dev-mode e2e testing.
 *
 * Registers two tools (echo + write_data), wraps with Bolyra auth,
 * and connects via stdio transport. Spawned as a subprocess by the
 * companion test file.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { withBolyraAuthStdio } from '../src/server-stdio';

const mcpServer = new McpServer(
  { name: 'bolyra-dev-test-server', version: '0.0.1' },
  { capabilities: { tools: {} } },
);

// Register tools BEFORE wrapping with Bolyra auth.
mcpServer.tool(
  'echo',
  'Echoes the input message',
  { message: z.string() },
  async ({ message }) => ({
    content: [{ type: 'text' as const, text: `echo: ${message}` }],
  }),
);

mcpServer.tool(
  'write_data',
  'Writes data (requires WRITE_DATA permission)',
  { value: z.string() },
  async ({ value }) => ({
    content: [{ type: 'text' as const, text: `wrote: ${value}` }],
  }),
);

// Wrap with Bolyra auth — write_data requires bit 1 (WRITE_DATA = 0b10).
// Pass mcpServer.server (the low-level Server) because that's where
// _requestHandlers lives and where setRequestHandler is defined.
withBolyraAuthStdio(mcpServer.server, {
  devMode: true,
  toolPolicy: { write_data: 2n },
});

// Connect via stdio and start serving.
const transport = new StdioServerTransport();
mcpServer.connect(transport).catch((err) => {
  process.stderr.write(`[dev-server] fatal: ${err}\n`);
  process.exit(1);
});
