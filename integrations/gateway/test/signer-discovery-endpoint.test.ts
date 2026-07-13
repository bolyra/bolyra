/**
 * GET /.well-known/bolyra-signers.json — Receipt Signer Discovery v1
 * (spec/receipt-signer-discovery-v1.md) served for the gateway's active
 * receipt signer. 404 when receipts are disabled (no signer to discover).
 */
import * as http from 'http';
import { createGatewayProxy } from '../src/proxy';
import type { GatewayConfig } from '../src/types';

function makeConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    target: 'http://localhost:19999/mcp',
    port: 4100,
    network: 'base-sepolia',
    devMode: true,
    nonce: { store: 'memory', maxProofAge: 300 },
    receipts: { enabled: true, output: 'file', dir: './receipts/' },
    health: { enabled: true, path: '/healthz' },
    ...overrides,
  } as GatewayConfig;
}

function get(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}${path}`, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode!, body: data }));
      })
      .on('error', reject);
  });
}

async function withGateway<T>(config: GatewayConfig, fn: (port: number) => Promise<T>): Promise<T> {
  const receipts: unknown[] = [];
  const gateway = createGatewayProxy({
    config,
    receiptWriter: { write: async (r: unknown) => void receipts.push(r), close: async () => {} } as any,
  });
  await new Promise<void>((resolve) => gateway.listen(0, resolve));
  const port = (gateway.address() as any).port;
  try {
    return await fn(port);
  } finally {
    await new Promise<void>((resolve) => gateway.close(() => resolve()));
  }
}

describe('/.well-known/bolyra-signers.json', () => {
  it('serves a valid v1 discovery document for the active signer', async () => {
    await withGateway(makeConfig(), async (port) => {
      const { status, body } = await get(port, '/.well-known/bolyra-signers.json');
      expect(status).toBe(200);
      const doc = JSON.parse(body);
      expect(doc.v).toBe(1);
      expect(typeof doc.issuer).toBe('string');
      expect(typeof doc.updatedAt).toBe('number');
      expect(doc.signers).toHaveLength(1);
      expect(doc.signers[0].alg).toBe('ES256K');
      expect(doc.signers[0].signer).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(typeof doc.signers[0].keyId).toBe('string');
    });
  });

  it('document round-trips through the canonical parser', async () => {
    // jest maps @bolyra/receipts to ../receipts/dist (committed convention,
    // same as every cross-package test here) — the parser ships in receipts
    // 0.9.0, so a stale dist means "build integrations/receipts", not a bug.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { parseSignerDiscovery, acceptedSigners } = require('@bolyra/receipts');
    if (typeof parseSignerDiscovery !== 'function') {
      throw new Error(
        'parseSignerDiscovery missing from the jest-mapped @bolyra/receipts dist — run `npm run build` in integrations/receipts (needs >=0.9.0 source)',
      );
    }
    await withGateway(makeConfig(), async (port) => {
      const { body } = await get(port, '/.well-known/bolyra-signers.json');
      const doc = parseSignerDiscovery(JSON.parse(body));
      expect(acceptedSigners(doc).size).toBe(1);
    });
  });

  it('returns 404 when receipts are disabled (no signer to discover)', async () => {
    const config = makeConfig({ receipts: { enabled: false, output: 'file', dir: './receipts/' } as any });
    const receiptsOff = createGatewayProxy({ config });
    await new Promise<void>((resolve) => receiptsOff.listen(0, resolve));
    const port = (receiptsOff.address() as any).port;
    try {
      const { status } = await get(port, '/.well-known/bolyra-signers.json');
      expect(status).toBe(404);
    } finally {
      await new Promise<void>((resolve) => receiptsOff.close(() => resolve()));
    }
  });

  it('only answers GET', async () => {
    await withGateway(makeConfig(), async (port) => {
      const status = await new Promise<number>((resolve, reject) => {
        const req = http.request(
          { host: '127.0.0.1', port, path: '/.well-known/bolyra-signers.json', method: 'POST' },
          (res) => {
            res.resume();
            resolve(res.statusCode!);
          },
        );
        req.on('error', reject);
        req.end();
      });
      expect(status).not.toBe(200);
    });
  });
});
