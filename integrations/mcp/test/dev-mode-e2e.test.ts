/**
 * End-to-end integration test: spawns the dev MCP server as a subprocess
 * over stdio and exercises the Bolyra auth wrapper through the real
 * MCP protocol path.
 *
 * Three scenarios:
 *   1. Valid dev proof + permitted tool   → success
 *   2. Insufficient permissions           → policy denied
 *   3. No proof bundle                    → auth required
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof } from '../src/client';
import * as path from 'node:path';

jest.setTimeout(30_000);

const DEV_SERVER_PATH = path.resolve(__dirname, 'dev-server.ts');

/** Spin up a client connected to the dev server subprocess. */
async function createTestClient(): Promise<Client> {
  const transport = new StdioClientTransport({
    command: 'npx',
    args: ['tsx', DEV_SERVER_PATH],
    stderr: 'pipe',
  });

  const client = new Client(
    { name: 'bolyra-e2e-test-client', version: '0.0.1' },
    { capabilities: {} },
  );

  await client.connect(transport);
  return client;
}

describe('dev-mode e2e (subprocess stdio)', () => {
  let client: Client;

  afterEach(async () => {
    try {
      await client?.close();
    } catch {
      // server may already be gone
    }
  });

  it('valid dev proof + permitted tool returns echo result', async () => {
    client = await createTestClient();

    // All permissions (0b11111111) — echo has no policy requirement.
    const { human, agent } = await createDevIdentities();
    const auth = await attachBolyraProof(human, agent, { devMode: true });

    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'hello bolyra' },
      _meta: { bolyra: auth.meta.bolyra },
    });

    expect(result.isError).toBeFalsy();
    const text = (result.content as Array<{ type: string; text: string }>)[0]?.text;
    expect(text).toBe('echo: hello bolyra');
  });

  it('insufficient permissions triggers policy denied', async () => {
    client = await createTestClient();

    // READ_DATA only (0b01) — write_data requires WRITE_DATA (0b10).
    const { human, agent } = await createDevIdentities({
      permissionBitmask: 0b01n,
    });
    const auth = await attachBolyraProof(human, agent, { devMode: true });

    const result = await client.callTool({
      name: 'write_data',
      arguments: { value: 'secret' },
      _meta: { bolyra: auth.meta.bolyra },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]?.text;
    expect(text).toContain('policy denied');
  });

  it('missing proof bundle triggers auth required', async () => {
    client = await createTestClient();

    // Call echo with no _meta.bolyra at all.
    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'no auth' },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]?.text;
    expect(text).toContain('auth required');
  });
});
