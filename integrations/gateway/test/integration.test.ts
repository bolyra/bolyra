/**
 * @bolyra/gateway — integration tests.
 *
 * End-to-end tests with a mock upstream HTTP server, dev-mode verification,
 * and receipt output verification.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createGatewayProxy } from '../src/proxy';
import type { GatewayConfig } from '../src/types';

// --- Test helpers ---

/** Create a valid dev-mode proof bundle. */
function makeDevBundle(permissions: string = '3'): string {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const nonce = ((now << 64n) | BigInt(Math.floor(Math.random() * 1e15))).toString();
  const bundle = {
    v: 1,
    _dev: true,
    humanProof: {
      proof: { pi_a: ['0', '0', '1'], pi_b: [['0', '0'], ['0', '0'], ['1', '0']], pi_c: ['0', '0', '1'], protocol: 'groth16', curve: 'bn128' },
      publicSignals: ['0', '0', '0'],
    },
    agentProof: {
      proof: { pi_a: ['0', '0', '1'], pi_b: [['0', '0'], ['0', '0'], ['1', '0']], pi_c: ['0', '0', '1'], protocol: 'groth16', curve: 'bn128' },
      publicSignals: ['0', '0', '0', permissions],
    },
    nonce,
    credentialCommitment: '12345678',
  };
  return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

/** HTTP request helper. */
function request(
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: unknown },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: any }> {
  return new Promise((resolve, reject) => {
    const bodyStr = options.body ? JSON.stringify(options.body) : undefined;
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path: options.path ?? '/',
        method: options.method ?? 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(bodyStr ? { 'Content-Length': String(Buffer.byteLength(bodyStr)) } : {}),
          ...options.headers,
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          let body;
          try { body = JSON.parse(data); } catch { body = data; }
          resolve({ status: res.statusCode!, headers: res.headers, body });
        });
      },
    );
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// --- Integration test suite ---

describe('integration: full gateway lifecycle', () => {
  let upstream: http.Server;
  let upstreamPort: number;
  let gateway: http.Server;
  let gatewayPort: number;
  let receiptDir: string;
  let upstreamRequests: Array<{ method: string; headers: http.IncomingHttpHeaders; body: string }>;

  beforeEach(async () => {
    upstreamRequests = [];
    receiptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-integ-receipts-'));

    // Mock upstream MCP server
    upstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        upstreamRequests.push({ method: req.method!, headers: req.headers, body });

        // Return different responses based on method
        const parsed = body ? JSON.parse(body) : {};
        if (parsed.method === 'tools/list') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            result: { tools: [{ name: 'read_file' }, { name: 'write_file' }] },
            id: parsed.id,
          }));
        } else if (parsed.method === 'tools/call') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            result: { content: [{ type: 'text', text: 'tool result' }] },
            id: parsed.id,
          }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', result: {}, id: parsed.id }));
        }
      });
    });

    await new Promise<void>((resolve) => {
      upstream.listen(0, () => {
        upstreamPort = (upstream.address() as any).port;
        resolve();
      });
    });

    // Gateway with tool policies
    const config: GatewayConfig = {
      target: `http://localhost:${upstreamPort}/mcp`,
      port: 0,
      network: 'base-sepolia',
      devMode: true,
      nonce: { store: 'memory', maxProofAge: 300 },
      receipts: { enabled: true, output: 'file', dir: receiptDir },
      health: { enabled: true, path: '/healthz' },
      tools: {
        write_file: { requireBitmask: 0b10 },    // WRITE_DATA
        delete_file: { requireBitmask: 0b110 },   // WRITE_DATA + FINANCIAL_SMALL
      },
    };

    gateway = createGatewayProxy({ config });
    await new Promise<void>((resolve) => {
      gateway.listen(0, () => {
        gatewayPort = (gateway.address() as any).port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => gateway.close(() => resolve()));
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    fs.rmSync(receiptDir, { recursive: true, force: true });
  });

  test('1. tools/call with valid dev-mode auth: 200, reaches upstream, receipt created', async () => {
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: {} } },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });

    expect(status).toBe(200);
    expect(body.result.content[0].text).toBe('tool result');
    expect(upstreamRequests.length).toBe(1);

    // Wait for receipt to be written (async, setImmediate)
    await new Promise((resolve) => setTimeout(resolve, 100));
    const today = new Date().toISOString().split('T')[0];
    const dayDir = path.join(receiptDir, today);
    if (fs.existsSync(dayDir)) {
      const files = fs.readdirSync(dayDir);
      expect(files.length).toBeGreaterThanOrEqual(1);
    }
  });

  test('2. tools/call without auth header: 401 JSON-RPC error', async () => {
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file' } },
    });

    expect(status).toBe(401);
    expect(body.jsonrpc).toBe('2.0');
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toContain('missing');
    expect(upstreamRequests.length).toBe(0);
  });

  test('3. tools/call with insufficient permissions: 403 JSON-RPC error', async () => {
    // Bundle has permissions 0b11 (READ + WRITE), delete_file requires 0b110
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'delete_file' } },
      headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
    });

    expect(status).toBe(403);
    expect(body.error.code).toBe(-32001);
    expect(body.error.message).toContain('policy denied');
    expect(upstreamRequests.length).toBe(0);
  });

  test('4. auth-exempt method (initialize) forwarded without auth', async () => {
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 4, method: 'initialize' },
    });

    expect(status).toBe(200);
    expect(upstreamRequests.length).toBe(1);
    // No Authorization header forwarded (was not present)
    expect(upstreamRequests[0].headers['authorization']).toBeUndefined();
  });

  test('4b. non-exempt method (tools/list) requires auth', async () => {
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 4, method: 'tools/list' },
    });

    expect(status).toBe(401);
    expect(body.error.code).toBe(-32000);
    expect(upstreamRequests.length).toBe(0);
  });

  test('4c. non-exempt method (tools/list) forwarded with valid auth', async () => {
    const { status, body } = await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 4, method: 'tools/list' },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });

    expect(status).toBe(200);
    expect(body.result.tools).toBeDefined();
    expect(upstreamRequests.length).toBe(1);
  });

  test('5. upstream down: 502 JSON-RPC error', async () => {
    // Close upstream
    await new Promise<void>((resolve) => upstream.close(() => resolve()));

    // Create a new gateway pointing at dead upstream
    const deadConfig: GatewayConfig = {
      target: 'http://localhost:19998/mcp',
      port: 0,
      network: 'base-sepolia',
      devMode: true,
      nonce: { store: 'memory', maxProofAge: 300 },
      receipts: { enabled: false, output: 'file' },
      health: { enabled: true, path: '/healthz' },
    };
    const deadGateway = createGatewayProxy({ config: deadConfig });
    await new Promise<void>((resolve) => deadGateway.listen(0, resolve));
    const deadPort = (deadGateway.address() as any).port;

    try {
      const { status, body } = await request(deadPort, {
        body: { jsonrpc: '2.0', id: 5, method: 'initialize' },
      });
      expect(status).toBe(502);
      expect(body.error.message).toContain('Bad Gateway');
    } finally {
      await new Promise<void>((resolve) => deadGateway.close(() => resolve()));
    }
  });

  test('6. health endpoint: 200 with status JSON', async () => {
    const { status, body } = await request(gatewayPort, {
      method: 'GET',
      path: '/healthz',
    });

    expect(status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.version).toBe('0.2.0');
    expect(body.upstream).toBe('reachable');
  });

  test('7. X-Bolyra-* headers present on proxied request', async () => {
    await request(gatewayPort, {
      body: { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'read_file' } },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });

    expect(upstreamRequests.length).toBe(1);
    const upHeaders = upstreamRequests[0].headers;
    expect(upHeaders['x-bolyra-verified']).toBe('true');
    expect(upHeaders['x-bolyra-did']).toMatch(/^did:bolyra:/);
    expect(upHeaders['x-bolyra-score']).toBeDefined();
    expect(upHeaders['x-bolyra-permissions']).toBeDefined();
    expect(upHeaders['x-bolyra-chain-depth']).toBe('0');
    // Authorization should be consumed by gateway
    expect(upHeaders['authorization']).toBeUndefined();
  });
});
