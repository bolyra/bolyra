/**
 * Credential binding in packaged Core mode (--dev).
 *
 * Dev mode mocks proof verification, so the permission mask inside a bundle
 * is self-asserted. When the gateway config carries a `credentials` section
 * (static registry: commitment -> granted mask), every claim MUST match the
 * registered credential — the packaged equivalent of the verified-actions
 * demo's HostOptions.credentials map (and of production's resolveCredential +
 * Poseidon3 scopeCommitment binding, where a forged mask cannot produce a
 * valid proof).
 *
 * Pinned behavior:
 *   - configured + matching claim        -> ALLOW (forwarded upstream)
 *   - configured + forged mask           -> 401 credential_mismatch + signed deny receipt
 *   - configured + unknown commitment    -> 401 credential_unknown + signed deny receipt
 *   - configured + expired registration  -> 401 credential_expired + signed deny receipt
 *   - configured + delegation expansion  -> 401 credential_mismatch (narrowing only)
 *   - NOT configured                     -> current permissive dev behavior, allow
 *                                           receipts flagged self-asserted
 *   - production + static credentials    -> resolveCredential wired from config
 */

import * as http from 'http';
import { createGatewayProxy } from '../src/proxy';
import { createStaticCredentialResolver } from '../src/credential-binding';
import { verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import type { GatewayConfig, ReceiptWriter } from '../src/types';

const COMMITMENT = '12345678';

// Same dev bundle shape as signed-receipts.test.ts
function makeDevBundle(
  permissions: string = '3',
  opts: { commitment?: string; delegationChain?: unknown[]; dev?: boolean } = {},
): string {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const nonce = ((now << 64n) | BigInt(Math.floor(Math.random() * 1e15))).toString();
  const bundle: Record<string, unknown> = {
    v: opts.delegationChain ? 2 : 1,
    humanProof: { proof: {}, publicSignals: ['0', '0', '0'] },
    agentProof: { proof: {}, publicSignals: ['0', '0', '0', permissions] },
    nonce,
    credentialCommitment: opts.commitment ?? COMMITMENT,
    ...(opts.delegationChain ? { delegationChain: opts.delegationChain } : {}),
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

describe('credential binding in packaged --dev mode', () => {
  let upstream: http.Server;
  let upstreamPort: number;
  let upstreamHits: number;

  beforeAll((done) => {
    upstream = http.createServer((req, res) => {
      req.on('data', () => {});
      req.on('end', () => {
        upstreamHits += 1;
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
    upstreamHits = 0;
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
      credentials: {
        type: 'static',
        map: { [COMMITMENT]: { permissionBitmask: 3 } },
      },
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

  // ------------------------------------------------------------ enforcement

  it('ALLOWS a claim that matches the registered credential', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
      });
      expect(status).toBe(200);
    });
    expect(upstreamHits).toBe(1);
    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(true);
    // Enforced-binding allows are NOT flagged self-asserted.
    expect(signed[0].payload.decision.reasonCode).not.toContain('self-asserted');
    expect(verifyReceipt(signed[0])).toBe(true);
  });

  it('DENIES 401 fail-closed when the claimed mask does not match (forged bundle) with a signed credential_mismatch receipt', async () => {
    const { signed, raw, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        // Registered mask is 3 (READ|WRITE); bundle forges 255.
        headers: { Authorization: `Bolyra ${makeDevBundle('255')}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_mismatch');
    });
    expect(upstreamHits).toBe(0); // fail closed — never forwarded
    expect(raw).toHaveLength(0);
    expect(signed).toHaveLength(1);
    const receipt = signed[0];
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toContain('credential_mismatch');
    expect(receipt.payload.subject.credentialCommitment).toBe(COMMITMENT);
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('DENIES 401 for a commitment not registered with the gateway (credential_unknown)', async () => {
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { commitment: '99999999' })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_unknown');
    });
    expect(upstreamHits).toBe(0);
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
    expect(signed[0].payload.decision.reasonCode).toContain('credential_unknown');
    expect(verifyReceipt(signed[0])).toBe(true);
  });

  it('DENIES 401 when the registered credential is expired (credential_expired)', async () => {
    const { signed, writer } = makeCapturingWriter();
    const past = Math.floor(Date.now() / 1000) - 3600;
    const config = makeConfig({
      credentials: {
        type: 'static',
        map: { [COMMITMENT]: { permissionBitmask: 3, expiryTimestamp: String(past) } },
      },
    });
    await withGateway(config, writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3')}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_expired');
    });
    expect(upstreamHits).toBe(0);
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.reasonCode).toContain('credential_expired');
    expect(verifyReceipt(signed[0])).toBe(true);
  });

  it('DENIES a delegation chain that expands beyond the registered grant; allows genuine narrowing', async () => {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const link = (...scopes: string[]) => scopes.map((scope, i) => ({
      delegateeScope: scope,
      delegateeCommitment: (999 + i).toString(),
      delegateeExpiry: (now + 3600n).toString(),
      currentTimestamp: now.toString(),
      proof: { proof: {}, publicSignals: ['0'] },
    }));

    // Expansion: registered 3 (READ|WRITE), leaf claims bit 2 (FINANCIAL_SMALL).
    {
      const { signed, writer } = makeCapturingWriter();
      await withGateway(makeConfig(), writer, async (port) => {
        const { status } = await proxyRequest(port, {
          body: toolsCall('read_file'),
          headers: { Authorization: `Bolyra ${makeDevBundle('3', { delegationChain: link('7') })}` },
        });
        expect(status).toBe(401);
      });
      expect(signed).toHaveLength(1);
      expect(signed[0].payload.decision.allowed).toBe(false);
      expect(signed[0].payload.decision.reasonCode).toContain('credential_mismatch');
    }

    // Narrowing: registered 3, leaf narrows to 1 — allowed.
    {
      const { signed, writer } = makeCapturingWriter();
      await withGateway(makeConfig(), writer, async (port) => {
        const { status } = await proxyRequest(port, {
          body: toolsCall('read_file'),
          headers: { Authorization: `Bolyra ${makeDevBundle('3', { delegationChain: link('1') })}` },
        });
        expect(status).toBe(200);
      });
      expect(signed).toHaveLength(1);
      expect(signed[0].payload.decision.allowed).toBe(true);
    }

    // Hop-level expansion (Codex P1): registered 7, chain 7 -> 1 -> 3. The
    // leaf (3) is still under the root grant, but hop 2 widened 1 -> 3 —
    // narrowing is one-way at EVERY hop, so this must be denied.
    {
      const { signed, writer } = makeCapturingWriter();
      const config = makeConfig({
        credentials: { type: 'static', map: { [COMMITMENT]: { permissionBitmask: 7 } } },
      });
      await withGateway(config, writer, async (port) => {
        const { status, body } = await proxyRequest(port, {
          body: toolsCall('read_file'),
          headers: { Authorization: `Bolyra ${makeDevBundle('7', { delegationChain: link('1', '3') })}` },
        });
        expect(status).toBe(401);
        expect(body.error.message).toContain('credential_mismatch');
      });
      expect(signed).toHaveLength(1);
      expect(signed[0].payload.decision.allowed).toBe(false);
      expect(signed[0].payload.decision.reasonCode).toContain('credential_mismatch');
    }
  });

  it('DENIES a delegation chain with an expired hop (gateway clock, not the bundle-supplied timestamp)', async () => {
    // Codex round-2 P1: verifyDevBundle ignores delegateeExpiry, so a
    // narrowed-but-expired delegation hop would still verify. Bound Core
    // mode must reject expired hops like production does.
    const now = BigInt(Math.floor(Date.now() / 1000));
    const expiredLink = [{
      delegateeScope: '1',
      delegateeCommitment: '999',
      delegateeExpiry: (now - 3600n).toString(), // expired an hour ago
      currentTimestamp: (now - 7200n).toString(), // attacker-supplied, ignored
      proof: { proof: {}, publicSignals: ['0'] },
    }];
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { delegationChain: expiredLink })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_expired');
    });
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
    expect(signed[0].payload.decision.reasonCode).toContain('credential_expired');
  });

  it('DENIES a delegation chain that widens expiry beyond the registered credential or a prior hop', async () => {
    // Codex round-3 P2: Delegation.circom enforces delegateeExpiry <=
    // delegatorExpiry; bound Core mode must match.
    const now = BigInt(Math.floor(Date.now() / 1000));
    const registeredExpiry = now + 1000n;
    const config = makeConfig({
      credentials: {
        type: 'static',
        map: { [COMMITMENT]: { permissionBitmask: 3, expiryTimestamp: registeredExpiry.toString() } },
      },
    });
    const widenedLink = [{
      delegateeScope: '1',
      delegateeCommitment: '999',
      delegateeExpiry: (registeredExpiry + 99999n).toString(), // outlives the grant
      currentTimestamp: now.toString(),
      proof: { proof: {}, publicSignals: ['0'] },
    }];
    const { signed, writer } = makeCapturingWriter();
    await withGateway(config, writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { delegationChain: widenedLink })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_mismatch');
    });
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.reasonCode).toContain('credential_mismatch');
  });

  it('DENIES delegation hops with non-decimal wire fields (same strict parsing as production)', async () => {
    // Codex round-3 P2: production parses hop fields with a strict decimal
    // parser (integrations/mcp/src/verify.ts toBigInt); loose BigInt() would
    // accept hex forms production rejects.
    const now = BigInt(Math.floor(Date.now() / 1000));
    const hexLink = [{
      delegateeScope: '0x1',
      delegateeCommitment: '999',
      delegateeExpiry: (now + 3600n).toString(),
      currentTimestamp: now.toString(),
      proof: { proof: {}, publicSignals: ['0'] },
    }];
    const { signed, writer } = makeCapturingWriter();
    await withGateway(makeConfig(), writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { delegationChain: hexLink })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_mismatch');
    });
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
  });

  it('DENIES delegation hop scopes that violate the cumulative-bit encoding the circuits enforce', async () => {
    // Registered grant 31 (bits 0-4, cumulative-valid). Hop narrows to 16
    // (FINANCIAL_UNLIMITED without FINANCIAL_SMALL/MEDIUM) — a mask the
    // AgentPolicy/Delegation circuits would never accept.
    const now = BigInt(Math.floor(Date.now() / 1000));
    const badMaskLink = [{
      delegateeScope: '16',
      delegateeCommitment: '999',
      delegateeExpiry: (now + 3600n).toString(),
      currentTimestamp: now.toString(),
      proof: { proof: {}, publicSignals: ['0'] },
    }];
    const config = makeConfig({
      credentials: { type: 'static', map: { [COMMITMENT]: { permissionBitmask: 31 } } },
    });
    const { signed, writer } = makeCapturingWriter();
    await withGateway(config, writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('31', { delegationChain: badMaskLink })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toContain('credential_mismatch');
    });
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
  });

  it('static resolver returns null for expired registrations (production must not resolve expired credentials)', async () => {
    // Codex P1: verifyBundle only docks 20 score for an expired credential —
    // an otherwise-perfect proof would still pass at 80. The resolver must
    // fail closed instead.
    const past = String(Math.floor(Date.now() / 1000) - 3600);
    const resolver = createStaticCredentialResolver({
      type: 'static',
      map: { [COMMITMENT]: { permissionBitmask: '3', expiryTimestamp: past } },
    });
    expect(await resolver!(COMMITMENT)).toBeNull();
  });

  // --------------------------------------------------- unconfigured dev mode

  it('preserves permissive dev behavior when NO credentials are configured, but flags allow receipts self-asserted', async () => {
    const { signed, writer } = makeCapturingWriter();
    const config = makeConfig({ credentials: undefined });
    await withGateway(config, writer, async (port) => {
      const { status } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        // Any mask, any commitment goes through — current 0.3.0 behavior.
        headers: { Authorization: `Bolyra ${makeDevBundle('255', { commitment: '424242' })}` },
      });
      expect(status).toBe(200);
    });
    expect(upstreamHits).toBe(1);
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(true);
    // The tradeoff is visible on the receipt itself.
    expect(signed[0].payload.decision.reasonCode).toContain('self-asserted');
    expect(verifyReceipt(signed[0])).toBe(true);
  });

  // -------------------------------------------------------------- production

  it('production mode wires a resolveCredential from static credentials (Poseidon3 scopeCommitment binding path)', async () => {
    const resolver = createStaticCredentialResolver({
      type: 'static',
      map: {
        [COMMITMENT]: { permissionBitmask: '3', expiryTimestamp: '1893456000' },
      },
    });
    expect(resolver).toBeDefined();
    const credential = await resolver!(COMMITMENT);
    expect(credential).not.toBeNull();
    expect(credential!.permissionBitmask).toBe(3n);
    expect(credential!.expiryTimestamp).toBe(1893456000n);
    expect(credential!.commitment).toBe(BigInt(COMMITMENT));
    expect(await resolver!('99999999')).toBeNull();
  });

  it('production DENY: commitment not in static credentials yields 401 "no credential found" with a signed receipt', async () => {
    // With static credentials configured, production mode no longer throws
    // "resolveCredential is required" — it resolves from the config map and
    // fails closed on unknown commitments (before any proof crypto runs).
    const { signed, writer } = makeCapturingWriter();
    const config = makeConfig({
      devMode: false,
      credentials: {
        type: 'static',
        map: { '55555555': { permissionBitmask: 3, expiryTimestamp: '1893456000' } },
      },
    });
    await withGateway(config, writer, async (port) => {
      const { status, body } = await proxyRequest(port, {
        body: toolsCall('read_file'),
        headers: { Authorization: `Bolyra ${makeDevBundle('3', { dev: false })}` },
      });
      expect(status).toBe(401);
      expect(body.error.message).toMatch(/no credential found/i);
    });
    expect(signed).toHaveLength(1);
    expect(signed[0].payload.decision.allowed).toBe(false);
    expect(verifyReceipt(signed[0])).toBe(true);
  });
});
