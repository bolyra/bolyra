import * as http from 'http';
import { createGatewayProxy } from '../src/proxy';
import type { GatewayConfig } from '../src/types';

// Helper: create a valid dev-mode proof bundle
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

// Helper: make HTTP request to proxy
function proxyRequest(
  port: number,
  options: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: unknown;
  },
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

describe('reverse proxy', () => {
  let upstream: http.Server;
  let upstreamPort: number;
  let gateway: http.Server;
  let gatewayPort: number;
  let lastUpstreamReq: { method: string; headers: http.IncomingHttpHeaders; body: string } | null;

  beforeEach((done) => {
    lastUpstreamReq = null;

    // Create mock upstream
    upstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        lastUpstreamReq = { method: req.method!, headers: req.headers, body };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', result: { content: [{ text: 'hello' }] }, id: 1 }));
      });
    });

    upstream.listen(0, () => {
      upstreamPort = (upstream.address() as any).port;

      const config: GatewayConfig = {
        target: `http://localhost:${upstreamPort}/mcp`,
        port: 0,
        network: 'base-sepolia',
        devMode: true,
        nonce: { store: 'memory', maxProofAge: 300 },
        receipts: { enabled: false, output: 'file' },
        health: { enabled: true, path: '/healthz' },
      };

      gateway = createGatewayProxy({ config });
      gateway.listen(0, () => {
        gatewayPort = (gateway.address() as any).port;
        done();
      });
    });
  });

  afterEach((done) => {
    gateway.close(() => {
      upstream.close(done);
    });
  });

  it('forwards auth-exempt methods (initialize, ping) without auth', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'initialize' },
    });
    expect(status).toBe(200);
    expect(body.result).toBeDefined();
    expect(lastUpstreamReq).not.toBeNull();
    // Authorization header should be stripped
    expect(lastUpstreamReq!.headers['authorization']).toBeUndefined();
  });

  it('requires auth for non-exempt methods like tools/list', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    });
    expect(status).toBe(401);
    expect(body.error.code).toBe(-32000);
  });

  it('forwards non-exempt methods with valid auth', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });
    expect(status).toBe(200);
    expect(body.result).toBeDefined();
    expect(lastUpstreamReq).not.toBeNull();
  });

  it('gates tools/call — returns 401 without auth', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file' } },
    });
    expect(status).toBe(401);
    expect(body.error.code).toBe(-32000);
    expect(lastUpstreamReq).toBeNull(); // Should NOT reach upstream
  });

  it('gates tools/call — forwards with valid auth', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file' } },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });
    expect(status).toBe(200);
    expect(body.result).toBeDefined();
    expect(lastUpstreamReq).not.toBeNull();
  });

  it('injects X-Bolyra-* headers on authenticated requests', async () => {
    await proxyRequest(gatewayPort, {
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file' } },
      headers: { Authorization: `Bolyra ${makeDevBundle()}` },
    });
    expect(lastUpstreamReq).not.toBeNull();
    expect(lastUpstreamReq!.headers['x-bolyra-verified']).toBe('true');
    expect(lastUpstreamReq!.headers['x-bolyra-did']).toBeDefined();
    expect(lastUpstreamReq!.headers['x-bolyra-score']).toBeDefined();
    expect(lastUpstreamReq!.headers['x-bolyra-permissions']).toBeDefined();
  });

  it('intercepts health endpoint', async () => {
    // Reset — the health probe sends a HEAD to the upstream which sets lastUpstreamReq
    lastUpstreamReq = null;
    const { status, body } = await proxyRequest(gatewayPort, {
      method: 'GET',
      path: '/healthz',
    });
    expect(status).toBe(200);
    expect(body.version).toBe(require('../package.json').version);
    // The health probe sends a HEAD to upstream, which is expected.
    // But the original request body should NOT be forwarded.
    if (lastUpstreamReq) {
      expect(lastUpstreamReq.method).toBe('HEAD'); // Only the probe, not the client request
    }
  });

  it('returns 502 when upstream is unreachable', async () => {
    // Create a separate gateway pointing at a dead port
    const deadConfig: GatewayConfig = {
      target: 'http://localhost:19999/mcp', // No server listening
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
      const { status, body } = await proxyRequest(deadPort, {
        body: { jsonrpc: '2.0', id: 1, method: 'initialize' },
      });
      expect(status).toBe(502);
      expect(body.error.message).toContain('Bad Gateway');
    } finally {
      await new Promise<void>((resolve) => deadGateway.close(() => resolve()));
    }
  });

  it('returns 400 for malformed JSON body', async () => {
    const { status, body } = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port: gatewayPort,
          path: '/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': '12',
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            resolve({ status: res.statusCode!, body: JSON.parse(data) });
          });
        },
      );
      req.on('error', reject);
      req.write('{not valid}}');
      req.end();
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe(-32700);
  });

  it('returns 400 for JSON-RPC batch (array)', async () => {
    const { status, body } = await proxyRequest(gatewayPort, {
      body: [
        { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x' } },
        { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'y' } },
      ],
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe(-32600);
  });
});
