import * as http from 'http';
import { createGatewayMiddleware, extractToolName } from '../src/middleware';
import type { GatewayConfig, GatewayRequest, GatewayMiddlewareOptions } from '../src/types';

function makeConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    target: 'http://localhost:3000/mcp',
    port: 4100,
    network: 'base-sepolia',
    devMode: true, // Use dev mode for tests
    nonce: { store: 'memory', maxProofAge: 300 },
    receipts: { enabled: false, output: 'file' },
    health: { enabled: true, path: '/healthz' },
    ...overrides,
  };
}

/** Create a valid dev-mode proof bundle (base64-encoded). */
function makeDevBundle(overrides: Record<string, unknown> = {}): string {
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
      publicSignals: ['0', '0', '0', '3'], // permissionBitmask = 3 (READ + WRITE)
    },
    nonce,
    credentialCommitment: '12345678',
    ...overrides,
  };
  return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

/** Helper: invoke middleware on a mock request. */
async function invokeMiddleware(
  config: GatewayConfig,
  headers: Record<string, string>,
  body?: Record<string, unknown>,
  toolName?: string,
): Promise<{ authorized: boolean; status?: number; responseBody?: any }> {
  const options: GatewayMiddlewareOptions = { config };
  const middleware = createGatewayMiddleware(options);

  return new Promise((resolve) => {
    const req = {
      headers,
      jsonRpcBody: body as any,
    } as GatewayRequest;

    const chunks: Buffer[] = [];
    let statusCode = 200;

    const res = {
      writeHead(status: number, hdrs?: Record<string, string>) {
        statusCode = status;
        return res;
      },
      setHeader(_name: string, _value: string) {
        return res;
      },
      end(data?: string) {
        if (data) chunks.push(Buffer.from(data));
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
        resolve({ authorized: false, status: statusCode, responseBody: body });
      },
    } as unknown as http.ServerResponse;

    middleware(req, res, toolName).then((authorized) => {
      if (authorized) {
        resolve({ authorized: true });
      }
    });
  });
}

describe('auth middleware', () => {
  it('returns 401 when Authorization header is missing', async () => {
    const result = await invokeMiddleware(makeConfig(), {});
    expect(result.authorized).toBe(false);
    expect(result.status).toBe(401);
    expect(result.responseBody.error.code).toBe(-32000);
    expect(result.responseBody.error.message).toContain('missing');
  });

  it('returns 401 when Authorization header has wrong scheme', async () => {
    const result = await invokeMiddleware(makeConfig(), {
      authorization: 'Bearer some-token',
    });
    expect(result.authorized).toBe(false);
    expect(result.status).toBe(401);
  });

  it('returns 401 when bundle is malformed (not base64)', async () => {
    const result = await invokeMiddleware(makeConfig(), {
      authorization: 'Bolyra not-valid-base64!!!',
    });
    expect(result.authorized).toBe(false);
    expect(result.status).toBe(401);
    expect(result.responseBody.error.message).toContain('malformed');
  });

  it('accepts valid dev-mode bundle', async () => {
    const result = await invokeMiddleware(
      makeConfig(),
      { authorization: `Bolyra ${makeDevBundle()}` },
    );
    expect(result.authorized).toBe(true);
  });

  it('returns 401 when dev bundle is sent to production mode', async () => {
    const config = makeConfig({ devMode: false });
    // Can't actually test production mode without resolveCredential,
    // but we can verify it rejects dev bundles
    const result = await invokeMiddleware(
      config,
      { authorization: `Bolyra ${makeDevBundle()}` },
    );
    // verifyBundle will reject because _dev: true in production mode
    expect(result.authorized).toBe(false);
    expect(result.status).toBe(401);
  });

  it('returns 403 when tool policy is insufficient', async () => {
    const config = makeConfig({
      tools: {
        delete_file: { requireBitmask: 0b110 }, // WRITE + FINANCIAL_SMALL
      },
    });
    // Bundle has permissionBitmask = 3 (0b11 = READ + WRITE), missing FINANCIAL_SMALL
    const result = await invokeMiddleware(
      config,
      { authorization: `Bolyra ${makeDevBundle()}` },
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'delete_file' } },
      'delete_file',
    );
    expect(result.authorized).toBe(false);
    expect(result.status).toBe(403);
    expect(result.responseBody.error.code).toBe(-32001);
    expect(result.responseBody.error.message).toContain('policy denied');
  });

  it('allows tool call when policy is satisfied', async () => {
    const config = makeConfig({
      tools: {
        read_file: { requireBitmask: 0b01 }, // READ only
      },
    });
    const result = await invokeMiddleware(
      config,
      { authorization: `Bolyra ${makeDevBundle()}` },
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file' } },
      'read_file',
    );
    expect(result.authorized).toBe(true);
  });

  it('JSON-RPC error format is correct', async () => {
    const result = await invokeMiddleware(makeConfig(), {});
    expect(result.responseBody).toEqual(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: null,
        error: expect.objectContaining({
          code: expect.any(Number),
          message: expect.any(String),
        }),
      }),
    );
  });
});

describe('extractToolName', () => {
  it('extracts tool name from tools/call body', () => {
    expect(extractToolName({ params: { name: 'write_file' } })).toBe('write_file');
  });

  it('returns undefined for missing params', () => {
    expect(extractToolName({})).toBeUndefined();
  });

  it('returns undefined for non-string name', () => {
    expect(extractToolName({ params: { name: 123 } })).toBeUndefined();
  });
});
