/**
 * Attacker client. No Bolyra credential. Just speaks raw MCP.
 *
 * Against the broken server: succeeds. Against the fixed server: rejected
 * with "Bolyra auth required" and never reaches the file handler.
 *
 * The target is a self-contained fake-credentials file shipped in
 * `demo-data/` so the demo is portable to any machine. In a real attack
 * the target would be `~/.ssh/id_rsa`, `.env`, AWS creds, OAuth tokens,
 * etc. — anything a prompt-injected agent could be tricked into reading
 * via an overpermissive MCP filesystem tool.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

async function main() {
  const which = process.argv[2]; // 'broken' | 'fixed'
  if (which !== 'broken' && which !== 'fixed') {
    throw new Error('usage: attacker-client.ts <broken|fixed>');
  }

  const transport = new StdioClientTransport({
    command: 'node',
    args: ['-r', 'ts-node/register', `src/server-${which}.ts`],
  });

  const client = new Client({ name: 'attacker', version: '0.0.0' }, { capabilities: {} });
  await client.connect(transport);

  const target = './demo-data/STOLEN-API-KEYS.txt';
  // eslint-disable-next-line no-console
  console.log(`\n[attacker → server-${which}] calling read_file("${target}") with no Bolyra credential...\n`);

  try {
    const result = await client.callTool({
      name: 'read_file',
      arguments: { path: target },
    });
    if ((result as any).isError) {
      // eslint-disable-next-line no-console
      console.log(`[server-${which}] REJECTED:`, (result as any).content?.[0]?.text);
    } else {
      // eslint-disable-next-line no-console
      console.log(`[server-${which}] LEAKED file contents (first 200 chars):`);
      const text = (result as any).content?.[0]?.text ?? '';
      // eslint-disable-next-line no-console
      console.log(text.slice(0, 200));
    }
  } catch (err: unknown) {
    // eslint-disable-next-line no-console
    console.log(`[server-${which}] threw:`, err instanceof Error ? err.message : String(err));
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
