import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as readline from 'readline';

const SHIELD_BIN = path.resolve(__dirname, '../dist/cli.js');
const MOCK_SERVER_CMD = `npx tsx ${path.resolve(__dirname, 'mock-server.ts')}`;

function makeDevBundle(permissionBitmask: number, seed: number): any {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const entropy = BigInt(seed);
  const nonce = ((nowSec << 64n) | entropy).toString();
  return {
    v: 1,
    _dev: true,
    humanProof: {
      pi_a: ['0', '0', '1'],
      pi_b: [['0', '0'], ['0', '0'], ['1', '0']],
      pi_c: ['0', '0', '1'],
      publicSignals: ['0', '0', '0', '0'],
    },
    agentProof: {
      pi_a: ['0', '0', '1'],
      pi_b: [['0', '0'], ['0', '0'], ['1', '0']],
      pi_c: ['0', '0', '1'],
      publicSignals: ['0', '0', '0', String(permissionBitmask)],
    },
    nonce,
    credentialCommitment: String(seed),
  };
}

describe('@bolyra/shield', () => {
  let shield: ChildProcess;
  let responseQueue: Array<(value: any) => void> = [];
  let scenario1Bundle: any;

  beforeAll(done => {
    shield = spawn('node', [
      SHIELD_BIN,
      '--server', MOCK_SERVER_CMD,
      '--dev',
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    // Single readline for all responses
    const rl = readline.createInterface({ input: shield.stdout! });
    rl.on('line', (line: string) => {
      try {
        const parsed = JSON.parse(line);
        const resolver = responseQueue.shift();
        if (resolver) resolver(parsed);
      } catch { /* ignore non-JSON */ }
    });

    // Wait for banner on stderr
    shield.stderr!.once('data', () => setTimeout(done, 1000));
  });

  afterAll(() => {
    shield.kill('SIGTERM');
  });

  function send(msg: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('timeout')), 8000);
      responseQueue.push((val) => {
        clearTimeout(timeout);
        resolve(val);
      });
      shield.stdin!.write(JSON.stringify(msg) + '\n');
    });
  }

  test('Scenario 1: verified agent calls read_file — allowed', async () => {
    scenario1Bundle = makeDevBundle(1, 3001);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 1,
      params: { name: 'read_file', arguments: {}, _meta: { bolyra: scenario1Bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.result.content[0].text).toContain('executed read_file');
  });

  test('Scenario 2: verified agent calls write_file with WRITE_DATA — allowed', async () => {
    const bundle = makeDevBundle(3, 3002);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 2,
      params: { name: 'write_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.result.content[0].text).toContain('executed write_file');
  });

  test('Scenario 3: read-only agent blocked from write_file', async () => {
    const bundle = makeDevBundle(1, 3003);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 3,
      params: { name: 'write_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.error).toBeDefined();
    expect(res.error.message).toContain('policy denied');
  });

  test('Scenario 4: replay attack blocked (exact same bundle as scenario 1)', async () => {
    // Use the exact same bundle object — same nonce string
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 4,
      params: { name: 'read_file', arguments: {}, _meta: { bolyra: scenario1Bundle } },
    });
    expect(res.error).toBeDefined();
    expect(res.error.message).toMatch(/replay|Nonce already used/i);
  });

  test('Scenario 5: unknown tool allowed when defaultDeny is off (baseline)', async () => {
    const bundle = makeDevBundle(0b11111111, 3005);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 5,
      params: { name: 'unknown_tool', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.result.content[0].text).toContain('executed unknown_tool');
  });
});

describe('@bolyra/shield (defaultDeny)', () => {
  let shield: ChildProcess;
  let responseQueue: Array<(value: any) => void> = [];

  beforeAll(done => {
    const fs = require('fs');
    const tmpConfig = path.resolve(__dirname, 'shield-deny.yaml');
    fs.writeFileSync(tmpConfig, [
      'devMode: true',
      'defaultDeny: true',
      'tools:',
      '  read_file:',
      '    requireBitmask: 1',
    ].join('\n'));

    shield = spawn('node', [
      SHIELD_BIN,
      '--server', MOCK_SERVER_CMD,
      '--config', tmpConfig,
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    const rl = readline.createInterface({ input: shield.stdout! });
    rl.on('line', (line: string) => {
      try {
        const parsed = JSON.parse(line);
        const resolver = responseQueue.shift();
        if (resolver) resolver(parsed);
      } catch { /* ignore non-JSON */ }
    });

    shield.stderr!.once('data', () => setTimeout(done, 1000));
  });

  afterAll(() => {
    shield.kill('SIGTERM');
    const fs = require('fs');
    try { fs.unlinkSync(path.resolve(__dirname, 'shield-deny.yaml')); } catch {}
  });

  function send(msg: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('timeout')), 8000);
      responseQueue.push((val) => {
        clearTimeout(timeout);
        resolve(val);
      });
      shield.stdin!.write(JSON.stringify(msg) + '\n');
    });
  }

  test('known tool with valid proof — allowed', async () => {
    const bundle = makeDevBundle(1, 4001);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 1,
      params: { name: 'read_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.result.content[0].text).toContain('executed read_file');
  });

  test('unknown tool with valid proof — denied by defaultDeny', async () => {
    const bundle = makeDevBundle(0b11111111, 4002);
    const res = await send({
      jsonrpc: '2.0', method: 'tools/call', id: 2,
      params: { name: 'unknown_tool', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.error).toBeDefined();
    expect(res.error.message).toContain('not in policy');
    expect(res.error.message).toContain('defaultDeny');
  });
});
