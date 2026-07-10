/**
 * Signed receipts on EVERY allow and deny decision — dev mode and production.
 *
 * The landing-page claim is "ES256K-signed receipt for every decision. Allow
 * or deny." These tests pin that behavior for the packaged proxy:
 *   - dev-mode allow  -> signed receipt (ES256K, verifies independently)
 *   - dev-mode deny   -> signed receipt (policy, replay)
 *   - prod-mode deny  -> signed receipt (dev bundle rejected, unknown credential)
 *   - missing/malformed bundle -> signed ANONYMOUS deny receipt
 *   - tampered receipts fail verifyReceipt
 *
 * Receipt signing follows examples/verified-actions-demo: createAuthReceipt +
 * signReceipt from @bolyra/receipts — same schema, same crypto.
 */

import * as http from 'http';
import { createGatewayProxy } from '../src/proxy';
import { verifyReceipt, verifyReceiptChain, GENESIS_PREV_RECEIPT_HASH } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import type { GatewayConfig, ReceiptWriter } from '../src/types';

// Helper: create a valid dev-mode proof bundle (same shape as proxy.test.ts)
function makeDevBundle(permissions: string = '3', opts: { dev?: boolean; nonce?: string } = {}): string {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const nonce = opts.nonce ?? ((now << 64n) | BigInt(Math.floor(Math.random() * 1e15))).toString();
  const bundle: Record<string, unknown> = {
    v: 1,
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
  if (opts.dev !== false) bundle._dev = true;
  return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

function proxyRequest(
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

/** Capturing receipt writer: signed receipts and raw (legacy unsigned) records. */
function makeCapturingWriter(): { signed: SignedReceipt[]; raw: Record<string, unknown>[]; writer: ReceiptWriter } {
  const signed: SignedReceipt[] = [];
  const raw: Record<string, unknown>[] = [];
  return {
    signed,
    raw,
    writer: {
      write: (r: SignedReceipt) => { signed.push(r); },
      writeRaw: (d: Record<string, unknown>) => { raw.push(d); },
    },
  };
}

function toolsCall(name: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name } };
}

describe('signed receipts on every decision', () => {
  let upstream: http.Server;
  let upstreamPort: number;
  let lastUpstreamHeaders: http.IncomingHttpHeaders | null;

  beforeAll((done) => {
    upstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        lastUpstreamHeaders = req.headers;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', result: { content: [] }, id: 1 }));
      });
    });
    upstream.listen(0, () => {
      upstreamPort = (upstream.address() as any).port;
      done();
    });
  });

  afterAll((done) => {
    upstream.close(done);
  });

  beforeEach(() => {
    lastUpstreamHeaders = null;
  });

  function makeConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
    return {
      target: `http://localhost:${upstreamPort}/mcp`,
      port: 0,
      network: 'base-sepolia',
      devMode: true,
      nonce: { store: 'memory', maxProofAge: 300 },
      receipts: { enabled: true, output: 'file' },
      health: { enabled: true, path: '/healthz' },
      tools: { transfer_funds: { requireBitmask: 28 } },
      ...overrides,
    };
  }

  async function withGateway<T>(
    config: GatewayConfig,
    writer: ReceiptWriter,
    fn: (port: number) => Promise<T>,
  ): Promise<T> {
    const gateway = createGatewayProxy({ config, receiptWriter: writer });
    await new Promise<void>((resolve) => gateway.listen(0, resolve));
    const port = (gateway.address() as any).port;
    try {
      return await fn(port);
    } finally {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
    }
  }

  // ---------------------------------------------------------------- dev mode

  it('dev-mode ALLOW emits an ES256K-signed receipt that verifies independently', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` },
      });
      expect(status).toBe(200);
    });

    expect(raw).toHaveLength(0); // no unsigned records — signed or nothing
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.signature.alg).toBe('ES256K');
    expect(receipt.payload.kind).toBe('bolyra.auth');
    expect(receipt.payload.decision.allowed).toBe(true);
    expect(receipt.payload.decision.reasonCode).toContain('read_file');
    expect(receipt.payload.decision.permissionBitmask).toBe('3');
    expect(receipt.payload.subject.rootDid).toMatch(/^did:bolyra:dev:/);
    // Independent verification: no gateway needed, just the receipt.
    expect(verifyReceipt(receipt)).toBe(true);
    // The forwarded request carries the receipt id so upstream logs correlate.
    expect(lastUpstreamHeaders?.['x-bolyra-receipt-id']).toBe(receipt.id);
  });

  it('dev-mode DENY (policy) emits a signed receipt with full context', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('transfer_funds'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` }, // has READ+WRITE, needs FINANCIAL
      });
      expect(status).toBe(403);
    });

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.signature.alg).toBe('ES256K');
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toContain('transfer_funds');
    expect(receipt.payload.subject.rootDid).toMatch(/^did:bolyra:dev:/);
    expect(receipt.payload.decision.score).toBe(100);
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('dev-mode DENY (nonce replay) emits a signed receipt', async () => {
    const { signed, writer } = makeCapturingWriter();
    const bundle = makeDevBundle();
    await withGateway(makeConfig(), writer, async (port) => {
      const first = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${bundle}` },
      });
      expect(first.status).toBe(200);
      const replay = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${bundle}` },
      });
      expect(replay.status).toBe(401);
    });

    expect(signed).toHaveLength(2); // one allow + one deny
    const deny = signed[1];
    expect(deny.payload.decision.allowed).toBe(false);
    expect(deny.payload.decision.reasonCode).toMatch(/replay/i);
    expect(deny.payload.subject.rootDid).not.toBe('');
    expect(verifyReceipt(deny)).toBe(true);
  });

  it('missing Authorization header emits a signed ANONYMOUS deny receipt', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, { body: toolsCall('read_file') });
      expect(status).toBe(401);
    });

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.subject.rootDid).toContain('anonymous');
    expect(receipt.payload.decision.score).toBe(0);
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('malformed bundle emits a signed anonymous deny receipt', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: 'Bolyra !!!not-base64-json!!!' },
      });
      expect(status).toBe(401);
    });

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.subject.rootDid).toContain('anonymous');
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('anonymous deny receipts are unique per decision and name the attempted tool', async () => {
    // Regression (Codex round-2 P2): constant anonymous payloads made two
    // denials in the same second hash to the same receipt id, and the receipt
    // could not say which tool was being called.
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      await proxyRequest(port, { body: toolsCall('read_file') });
      await proxyRequest(port, { body: toolsCall('transfer_funds') });
    });

    expect(signed).toHaveLength(2);
    expect(signed[0].id).not.toBe(signed[1].id);
    expect(signed[0].payload.decision.reasonCode).toContain('read_file');
    expect(signed[1].payload.decision.reasonCode).toContain('transfer_funds');
    expect(verifyReceipt(signed[0])).toBe(true);
    expect(verifyReceipt(signed[1])).toBe(true);
  });

  it('shapeless bundle (parses, but no proof material) fails closed with a signed anonymous deny receipt', async () => {
    // verifyBundle throws on bundles missing agentProof — the gateway must
    // turn that into a 401 deny with a signed receipt, not an unaudited 502.
    const { signed, raw, writer } = makeCapturingWriter();
    const shapeless = Buffer.from(JSON.stringify({ v: 1, _dev: true, nonce: '1', credentialCommitment: '1' })).toString('base64');
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${shapeless}` },
      });
      expect(status).toBe(401);
    });

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.subject.rootDid).toContain('anonymous');
    expect(verifyReceipt(receipt)).toBe(true);
  });

  // ------------------------------------------------------------- production

  it('production DENY (dev bundle rejected) emits a signed receipt', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig({ devMode: false }), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` }, // _dev bundle in prod
      });
      expect(status).toBe(401);
    });

    expect(raw).toHaveLength(0); // deny records must be SIGNED, not raw JSON
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.signature.alg).toBe('ES256K');
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toMatch(/dev bundle/i);
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('production DENY (unknown credential) emits a signed receipt', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    const config = makeConfig({ devMode: false });
    const gateway = createGatewayProxy({
      config,
      receiptWriter: writer,
      resolveCredential: async () => null, // credential not in registry
    });
    await new Promise<void>((resolve) => gateway.listen(0, resolve));
    const port = (gateway.address() as any).port;
    try {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { dev: false })}` },
      });
      expect(status).toBe(401);
    } finally {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
    }

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toMatch(/no credential found/i);
    expect(receipt.payload.subject.credentialCommitment).toBe('12345678');
    expect(verifyReceipt(receipt)).toBe(true);
  });

  // ---------------------------------------------------------- configured key

  it('uses the configured signing key (issuer, keyId, stable signer address)', async () => {
    const { signed, writer } = makeCapturingWriter();
    const config = makeConfig({
      receipts: {
        enabled: true,
        output: 'file',
        issuer: 'test-gateway',
        keyId: 'test-k1',
        privateKey: '0x' + '11'.repeat(32),
      },
    });
    await withGateway(config, writer, async (port) => {
      await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` },
      });
      await proxyRequest(port, { body: toolsCall('read_file') }); // anonymous deny
    });

    expect(signed).toHaveLength(2);
    expect(signed[0].payload.issuer).toBe('test-gateway');
    expect(signed[0].payload.keyId).toBe('test-k1');
    expect(signed[0].signature.keyId).toBe('test-k1');
    // Same key signs allow and deny — one pinnable trust anchor.
    expect(signed[1].signature.signer).toBe(signed[0].signature.signer);
    expect(verifyReceipt(signed[0], signed[0].signature.signer)).toBe(true);
    expect(verifyReceipt(signed[1], signed[0].signature.signer)).toBe(true);
  });

  it('policy denial with an explicit receiptSigner option writes a DENY receipt (never the verification allow)', async () => {
    // Regression (Codex P1): @bolyra/mcp's verifyBundle attaches a receipt
    // recording only the verification step (allowed=true for an authenticated
    // agent). The gateway must sign the FINAL decision — a 403 policy denial
    // must never be recorded as an allow.
    const { signed, raw, writer } = makeCapturingWriter();
    const config = makeConfig();
    const gateway = createGatewayProxy({
      config,
      receiptWriter: writer,
      receiptSigner: { issuer: 'embedder-gw', keyId: 'ek1', privateKey: '0x' + '22'.repeat(32) },
    });
    await new Promise<void>((resolve) => gateway.listen(0, resolve));
    const port = (gateway.address() as any).port;
    try {
      const { status } = await proxyRequest(port, {
        body: toolsCall('transfer_funds'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
      });
      expect(status).toBe(403);
    } finally {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
    }

    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
    expect(signed[0].payload.issuer).toBe('embedder-gw');
    expect(verifyReceipt(signed[0])).toBe(true);
  });

  it('delegated calls attribute actingDid to the chain leaf, not the root', async () => {
    const { signed, writer } = makeCapturingWriter();
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = ((now << 64n) | BigInt(Math.floor(Math.random() * 1e15))).toString();
    const bundle = Buffer.from(JSON.stringify({
      v: 2,
      _dev: true,
      humanProof: { proof: {}, publicSignals: ['0', '0', '0'] },
      agentProof: { proof: {}, publicSignals: ['0', '0', '0', '3'] },
      nonce,
      credentialCommitment: '12345678',
      delegationChain: [{
        delegateeScope: '1',
        delegateeCommitment: '999',
        delegateeExpiry: (now + 3600n).toString(),
        currentTimestamp: now.toString(),
        proof: { proof: {}, publicSignals: ['0'] },
      }],
    })).toString('base64');

    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${bundle}` },
      });
      expect(status).toBe(200);
    });

    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(true);
    expect(receipt.payload.decision.chainDepth).toBe(1);
    expect(receipt.payload.subject.actingDid).not.toBe(receipt.payload.subject.rootDid);
    expect(receipt.payload.subject.actingDid).toContain((999).toString(16).padStart(64, '0'));
    expect(verifyReceipt(receipt)).toBe(true);
  });

  // -------------------------------------------------------- tamper evidence

  it('tampered receipts fail verification', async () => {
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      await proxyRequest(port, {
        body: toolsCall('transfer_funds'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
      });
    });

    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(verifyReceipt(receipt)).toBe(true);

    // Flip the verdict deny -> allow
    const flipped: SignedReceipt = JSON.parse(JSON.stringify(receipt));
    flipped.payload.decision.allowed = true;
    expect(verifyReceipt(flipped)).toBe(false);

    // Rewrite the reason
    const reworded: SignedReceipt = JSON.parse(JSON.stringify(receipt));
    reworded.payload.decision.reasonCode = 'nothing to see here';
    expect(verifyReceipt(reworded)).toBe(false);
  });

  // ------------------------------------------------------------ hash chaining

  it('receipts from one gateway process form a verifiable hash chain (allow + deny + anonymous)', async () => {
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` },
      }); // allow
      await proxyRequest(port, {
        body: toolsCall('transfer_funds'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
      }); // policy deny
      await proxyRequest(port, { body: toolsCall('read_file') }); // anonymous deny
    });

    expect(signed).toHaveLength(3);
    // The startup probe must not consume seq 0 — the first WRITTEN receipt is genesis.
    expect(signed[0].payload.chain?.seq).toBe(0);
    expect(signed[0].payload.chain?.prevReceiptHash).toBe(GENESIS_PREV_RECEIPT_HASH);
    signed.forEach((r, i) => {
      expect(r.payload.chain?.seq).toBe(i);
      expect(r.receiptHash).toMatch(/^0x[0-9a-f]{64}$/);
    });
    const result = verifyReceiptChain(signed, { expectedSigner: signed[0].signature.signer });
    expect(result.issues).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it('deleting or reordering receipts in the gateway log breaks chain verification', async () => {
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      for (let i = 0; i < 4; i++) {
        await proxyRequest(port, {
          body: toolsCall('read_file'),
          headers: { Authorization: `Bolyra ${makeDevBundle()}` },
        });
      }
    });
    expect(signed).toHaveLength(4);

    const deleted = [signed[0], signed[2], signed[3]];
    expect(verifyReceiptChain(deleted).ok).toBe(false);

    const reordered = [signed[0], signed[2], signed[1], signed[3]];
    expect(verifyReceiptChain(reordered).ok).toBe(false);
  });

  // ------------------------------------------------------------- regressions

  it('receipts disabled + no custom writer: no receipts, no crash', async () => {
    const config = makeConfig({ receipts: { enabled: false, output: 'file' } });
    const gateway = createGatewayProxy({ config }); // no writer injected
    await new Promise<void>((resolve) => gateway.listen(0, resolve));
    const port = (gateway.address() as any).port;
    try {
      const ok = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` },
      });
      expect(ok.status).toBe(200);
      const denied = await proxyRequest(port, { body: toolsCall('read_file') });
      expect(denied.status).toBe(401);
    } finally {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
    }
  });

  it('custom writer still receives signed receipts when config.receipts.enabled is false', async () => {
    // Backward compat: an injected receiptWriter always sees decisions —
    // the enabled flag governs the config-based writer, not the seam.
    const { signed, writer } = makeCapturingWriter();
    const config = makeConfig({ receipts: { enabled: false, output: 'file' } });
    await withGateway(config, writer, async (port) => {
      await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle()}` },
      });
    });
    expect(signed).toHaveLength(1);
    expect(verifyReceipt(signed[0])).toBe(true);
  });
});
