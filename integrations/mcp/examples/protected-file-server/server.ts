#!/usr/bin/env npx tsx
/**
 * Protected File Server — Bolyra MCP example (server side).
 *
 * Three tools, each gated by a Bolyra permission bit:
 *   list_files  — READ_DATA (bit 0)
 *   read_file   — READ_DATA (bit 0)
 *   write_file  — WRITE_DATA (bit 1)
 *
 * The sandbox is a fresh subdirectory under os.tmpdir(). A sample file is
 * written on startup so list_files has something to show immediately.
 *
 * Spawned as a subprocess by client.ts.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { withBolyraAuthStdio } from '../../src/server-stdio';

// ---------------------------------------------------------------------------
// Sandbox setup
// ---------------------------------------------------------------------------

const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-fs-'));

// Seed a sample file so list_files is interesting from the first call.
fs.writeFileSync(
  path.join(SANDBOX, 'hello.txt'),
  'Hello from the Bolyra protected file server!\n',
);

/** Resolve a filename inside the sandbox, rejecting path traversal. */
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
  { name: 'bolyra-protected-file-server', version: '0.0.1' },
  { capabilities: { tools: {} } },
);

// READ_DATA (bit 0) — list sandbox contents
mcpServer.tool(
  'list_files',
  'List files in the protected sandbox directory',
  {},
  async () => {
    const names = fs.readdirSync(SANDBOX);
    return {
      content: [{ type: 'text' as const, text: names.join('\n') || '(empty)' }],
    };
  },
);

// READ_DATA (bit 0) — read one file by name
mcpServer.tool(
  'read_file',
  'Read a file from the protected sandbox by name',
  { name: z.string().describe('Filename inside the sandbox (no path separators)') },
  async ({ name }) => {
    const filePath = sandboxPath(name);
    if (!fs.existsSync(filePath)) {
      return { isError: true, content: [{ type: 'text' as const, text: `not found: ${name}` }] };
    }
    const content = fs.readFileSync(filePath, 'utf8');
    return { content: [{ type: 'text' as const, text: content }] };
  },
);

// WRITE_DATA (bit 1) — write a file by name
mcpServer.tool(
  'write_file',
  'Write content to a file in the protected sandbox (requires WRITE_DATA)',
  {
    name: z.string().describe('Filename to write (no path separators)'),
    content: z.string().describe('UTF-8 content to write'),
  },
  async ({ name, content }) => {
    const filePath = sandboxPath(name);
    fs.writeFileSync(filePath, content, 'utf8');
    return { content: [{ type: 'text' as const, text: `wrote ${content.length} bytes to ${name}` }] };
  },
);

// ---------------------------------------------------------------------------
// Bolyra auth wrapper
//   list_files + read_file require READ_DATA (0b01 = 1n)
//   write_file requires WRITE_DATA (0b10 = 2n)
// ---------------------------------------------------------------------------

withBolyraAuthStdio(mcpServer.server, {
  devMode: true,
  toolPolicy: {
    list_files: 1n,
    read_file: 1n,
    write_file: 2n,
  },
});

// ---------------------------------------------------------------------------
// Connect and serve
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
mcpServer.connect(transport).catch((err) => {
  process.stderr.write(`[file-server] fatal: ${err}\n`);
  process.exit(1);
});
