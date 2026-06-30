/**
 * Delegated client — READ_DATA only via 1-hop delegation.
 * search_recent_posts succeeds, add_bookmark is denied (requires WRITE_DATA).
 */
import { spawn } from 'child_process';
import * as readline from 'readline';
import * as path from 'path';
import { printHeader, printResult, jsonRpcInit, jsonRpcCall, proveReadOnly, tick } from './shared';

const SHIELD_BIN = path.resolve(__dirname, '../../../integrations/shield/dist/cli.js');
const MOCK_SERVER = `npx tsx ${path.resolve(__dirname, 'mock-x-server.ts')}`;
const CONFIG = path.resolve(__dirname, '../shield.yaml');

async function main() {
  printHeader('Scenario 3: Delegated Agent (READ_DATA only)');

  const auth = await proveReadOnly();
  console.log(`  Proof bundle generated (v=${auth.bundle.v}, chain depth=${auth.bundle.delegationChain?.length ?? 0})`);
  console.log(`  Effective permissions: READ_DATA only (0b00000001)\n`);

  const shield = spawn('node', [SHIELD_BIN, '--server', MOCK_SERVER, '--config', CONFIG], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const queue: Array<(v: any) => void> = [];
  const rl = readline.createInterface({ input: shield.stdout! });
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

  console.log('  Calling search_recent_posts with delegated proof...');
  const call2 = JSON.parse(jsonRpcCall(2, 'search_recent_posts', { query: 'zkp identity' }));
  call2.params._meta = { bolyra: auth.bundle };
  const res1 = await send(JSON.stringify(call2));
  printResult('search_recent_posts', res1);

  await tick();
  const auth2 = await proveReadOnly();
  console.log('  Calling add_bookmark with delegated proof...');
  const call3 = JSON.parse(jsonRpcCall(3, 'add_bookmark', { post_id: '789' }));
  call3.params._meta = { bolyra: auth2.bundle };
  const res2 = await send(JSON.stringify(call3));
  printResult('add_bookmark', res2);

  await tick();
  const auth3 = await proveReadOnly();
  console.log('  Calling create_article with delegated proof...');
  const call4 = JSON.parse(jsonRpcCall(4, 'create_article', { title: 'Unauthorized', body: 'Should fail' }));
  call4.params._meta = { bolyra: auth3.bundle };
  const res3 = await send(JSON.stringify(call4));
  printResult('create_article', res3);

  shield.kill('SIGTERM');
  console.log('  Result: Search allowed, bookmark + article denied. Delegation narrowed scope.\n');
}

main().catch(e => { console.error(e); process.exit(1); });
