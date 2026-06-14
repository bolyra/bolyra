import express from 'express';
import { credentialsRouter } from '../src/credentials';
import { apiKeyAuth } from '../src/auth';

// Mock the db module
jest.mock('../src/db', () => ({
  query: jest.fn(),
}));

import { query } from '../src/db';

const mockedQuery = query as jest.MockedFunction<typeof query>;

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(apiKeyAuth);
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use(credentialsRouter);
  return app;
}

// Minimal http helper (no supertest dependency)
async function request(
  app: express.Express,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') throw new Error('bad addr');
      const port = addr.port;

      const url = `http://127.0.0.1:${port}${path}`;
      const opts: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
      };
      if (body) opts.body = JSON.stringify(body);

      fetch(url, opts)
        .then(async (res) => {
          const json = await res.json().catch(() => null);
          server.close();
          resolve({ status: res.status, body: json });
        })
        .catch((err) => {
          server.close();
          throw err;
        });
    });
  });
}

const API_KEY = 'test-key-123';
const AUTH = { Authorization: `Bearer ${API_KEY}` };

const sampleCredential = {
  modelHash: '123456',
  operatorPublicKey: { x: '111', y: '222' },
  permissionBitmask: '7',
  expiryTimestamp: '1750000000',
  signature: { R8: { x: '333', y: '444' }, S: '555' },
  commitment: '999',
};

beforeAll(() => {
  process.env.REGISTRY_API_KEY = API_KEY;
});

afterEach(() => {
  jest.clearAllMocks();
});

describe('Auth middleware', () => {
  const app = buildApp();

  test('rejects request with no auth header', async () => {
    const res = await request(app, 'GET', '/v1/credentials/abc');
    expect(res.status).toBe(401);
  });

  test('rejects request with wrong key', async () => {
    const res = await request(app, 'GET', '/v1/credentials/abc', undefined, {
      Authorization: 'Bearer wrong-key',
    });
    expect(res.status).toBe(401);
  });

  test('health endpoint skips auth', async () => {
    const res = await request(app, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('POST /v1/credentials', () => {
  const app = buildApp();

  test('creates credential and returns 200', async () => {
    mockedQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 } as any);

    const res = await request(
      app,
      'POST',
      '/v1/credentials',
      { credential: sampleCredential },
      AUTH,
    );

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ commitment: '999', status: 'active' });
    expect(mockedQuery).toHaveBeenCalledTimes(1);
  });

  test('returns 400 for missing credential', async () => {
    const res = await request(app, 'POST', '/v1/credentials', {}, AUTH);
    expect(res.status).toBe(400);
  });
});

describe('GET /v1/credentials/:commitment', () => {
  const app = buildApp();

  test('returns credential when found', async () => {
    mockedQuery.mockResolvedValueOnce({
      rows: [{ credential_json: sampleCredential }],
      rowCount: 1,
    } as any);

    const res = await request(app, 'GET', '/v1/credentials/999', undefined, AUTH);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ credential: sampleCredential });
  });

  test('returns 404 when not found', async () => {
    mockedQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as any);

    const res = await request(app, 'GET', '/v1/credentials/missing', undefined, AUTH);

    expect(res.status).toBe(404);
  });
});

describe('DELETE /v1/credentials/:commitment', () => {
  const app = buildApp();

  test('soft-revokes and returns 200', async () => {
    mockedQuery.mockResolvedValueOnce({
      rows: [{ commitment: '999' }],
      rowCount: 1,
    } as any);

    const res = await request(app, 'DELETE', '/v1/credentials/999', undefined, AUTH);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ commitment: '999', status: 'revoked' });
  });

  test('returns 404 for non-existent credential', async () => {
    mockedQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as any);

    const res = await request(app, 'DELETE', '/v1/credentials/missing', undefined, AUTH);

    expect(res.status).toBe(404);
  });

  test('GET returns 404 after DELETE (revoked)', async () => {
    // Simulate revoke
    mockedQuery.mockResolvedValueOnce({
      rows: [{ commitment: '999' }],
      rowCount: 1,
    } as any);

    const app2 = buildApp();
    await request(app2, 'DELETE', '/v1/credentials/999', undefined, AUTH);

    // Subsequent GET — db returns empty because status != 'active'
    mockedQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as any);

    const res = await request(app2, 'GET', '/v1/credentials/999', undefined, AUTH);
    expect(res.status).toBe(404);
  });
});
