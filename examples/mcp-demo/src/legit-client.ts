/**
 * Legitimate client. Has a Bolyra human identity + agent credential, attaches
 * a fresh handshake proof to every tool call via attachBolyraProof().
 *
 * Against the fixed server: succeeds (~100ms proof overhead). Against the
 * broken server: also succeeds, but the broken server doesn't care either way
 * — that's the whole point.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { attachBolyraProof } from '@bolyra/mcp';
import { loadDemoIdentities, DEMO_SDK_CONFIG } from './shared';

async function main() {
  const which = process.argv[2]; // 'broken' | 'fixed'
  if (which !== 'broken' && which !== 'fixed') {
    throw new Error('usage: legit-client.ts <broken|fixed>');
  }

  const { human, credential } = await loadDemoIdentities();

  const transport = new StdioClientTransport({
    command: 'node',
    args: ['-r', 'ts-node/register', `src/server-${which}.ts`],
  });

  const client = new Client({ name: 'legit', version: '0.0.0' }, { capabilities: {} });
  await client.connect(transport);

  // Ask for a file the human authorized — a public docs file, not ~/.ssh.
  const target = './README.md';

  // eslint-disable-next-line no-console
  console.log(`\n[legit → server-${which}] generating Bolyra handshake proof...`);
  const t0 = Date.now();
  const auth = await attachBolyraProof(human, credential, DEMO_SDK_CONFIG);
  const proofMs = Date.now() - t0;
  // eslint-disable-next-line no-console
  console.log(`[legit → server-${which}] proof generated in ${proofMs}ms`);
  // eslint-disable-next-line no-console
  console.log(`[legit → server-${which}] calling read_file("${target}") with Bolyra credential...\n`);

  try {
    const t1 = Date.now();
    const result = await client.callTool({
      name: 'read_file',
      arguments: { path: target },
      _meta: auth.meta as any,
    });
    const callMs = Date.now() - t1;

    if ((result as any).isError) {
      // eslint-disable-next-line no-console
      console.log(`[server-${which}] REJECTED:`, (result as any).content?.[0]?.text);
    } else {
      const text = (result as any).content?.[0]?.text ?? '';
      // eslint-disable-next-line no-console
      console.log(`[server-${which}] OK in ${callMs}ms — returned ${text.length} chars (first 200):`);
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
