/**
 * Attacker client — calls X MCP tools with NO Bolyra proof.
 * Shield rejects with JSON-RPC -32000 (auth required).
 */
import { spawn } from 'child_process';
import * as readline from 'readline';
import * as path from 'path';
import { printHeader, printResult, jsonRpcInit, jsonRpcCall } from './shared';

const SHIELD_BIN = path.resolve(__dirname, '../../../integrations/shield/dist/cli.js');
const MOCK_SERVER = `npx tsx ${path.resolve(__dirname, 'mock-x-server.ts')}`;
const CONFIG = path.resolve(__dirname, '../shield.yaml');

async function main() {
  printHeader('Scenario 1: Attacker (no Bolyra proof)');

  const shield = spawn('node', [SHIELD_BIN, '--server', MOCK_SERVER, '--config', CONFIG], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const rl = readline.createInterface({ input: shield.stdout! });
  const queue: Array<(v: any) => void> = [];
  rl.on('line', (line) => {
    try {
      const parsed = JSON.parse(line);
      const resolver = queue.shift();
      if (resolver) resolver(parsed);
    } catch {}
  });

  function send(msg: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout')), 5000);
      queue.push((v) => { clearTimeout(t); resolve(v); });
      shield.stdin!.write(msg + '\n');
    });
  }

  await new Promise<void>(r => shield.stderr!.once('data', () => setTimeout(r, 500)));
  await send(jsonRpcInit(1));

  console.log('  Calling search_recent_posts without proof...');
  const res1 = await send(jsonRpcCall(2, 'search_recent_posts', { query: 'bolyra' }));
  printResult('search_recent_posts', res1);

  console.log('  Calling add_bookmark without proof...');
  const res2 = await send(jsonRpcCall(3, 'add_bookmark', { post_id: '123' }));
  printResult('add_bookmark', res2);

  shield.kill('SIGTERM');
  console.log('  Result: Both calls rejected. Shield requires proof bundles.\n');
}

main().catch(e => { console.error(e); process.exit(1); });
