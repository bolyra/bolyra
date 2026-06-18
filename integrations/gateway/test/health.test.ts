import * as http from 'http';
import { createHealthHandler } from '../src/health';
import type { GatewayConfig, GatewayRequest } from '../src/types';

function makeConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    target: 'http://localhost:19999/mcp', // unlikely port — will be unreachable by default
    port: 4100,
    network: 'base-sepolia',
    devMode: false,
    nonce: { store: 'memory', maxProofAge: 300 },
    receipts: { enabled: true, output: 'file', dir: './receipts/' },
    health: { enabled: true, path: '/healthz' },
    ...overrides,
  };
}

/** Helper: create a mock upstream server that responds to HEAD requests. */
function createMockUpstream(): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200);
      res.end();
    });
    server.listen(0, () => {
      const port = (server.address() as any).port;
      resolve({ server, port });
    });
  });
}

/** Helper: make an HTTP request and get the response. */
function makeRequest(handler: (req: GatewayRequest, res: http.ServerResponse) => void): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      handler(req as GatewayRequest, res);
    });
    server.listen(0, () => {
      const port = (server.address() as any).port;
      http.get(`http://localhost:${port}/healthz`, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          server.close();
          resolve({ status: res.statusCode!, body: JSON.parse(data) });
        });
      }).on('error', reject);
    });
  });
}

describe('health check', () => {
  it('returns 200 with status JSON when upstream is reachable', async () => {
    const { server: upstream, port } = await createMockUpstream();
    try {
      const config = makeConfig({ target: `http://localhost:${port}/mcp` });
      const handler = createHealthHandler(config);
      const { status, body } = await makeRequest(handler);

      expect(status).toBe(200);
      expect(body.status).toBe('ok');
      expect(body.version).toBe('0.1.0');
      expect(body.upstream).toBe('reachable');
      expect(typeof body.uptime).toBe('number');
    } finally {
      upstream.close();
    }
  });

  it('returns 503 when upstream is unreachable', async () => {
    const config = makeConfig({ target: 'http://localhost:19999/mcp' });
    const handler = createHealthHandler(config);
    const { status, body } = await makeRequest(handler);

    expect(status).toBe(503);
    expect(body.status).toBe('degraded');
    expect(body.upstream).toBe('unreachable');
  });

  it('shows dev mode when configured', async () => {
    const config = makeConfig({ devMode: true, target: 'http://localhost:19999/mcp' });
    const handler = createHealthHandler(config);
    const { body } = await makeRequest(handler);

    // M1: health endpoint no longer exposes mode, target, or internal config
    expect(body.status).toBeDefined();
    expect(body.version).toBeDefined();
  });
});
