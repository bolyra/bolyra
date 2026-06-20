/**
 * E2E test: HTTP Gateway path.
 *
 * Starts the MCP server on HTTP, starts @bolyra/gateway in dev mode,
 * and verifies:
 *   1. Health endpoint responds 200
 *   2. Initialize (auth-exempt) passes through without auth
 *   3. tools/call without Authorization returns 401
 *   4. tools/call with valid dev-mode Authorization succeeds
 *   5. Receipts are generated in the receipts directory
 */

import * as http from 'http';
import * as path from 'path';
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import { createGatewayProxy } from '@bolyra/gateway';
import { loadConfig } from '@bolyra/gateway';
import { createReceiptWriter } from '@bolyra/gateway';
import { MemoryNonceStore } from '@bolyra/mcp';
import { attachBolyraProof } from '@bolyra/mcp';
import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
} from '@bolyra/sdk';
import { startHttp } from '../src/server';

const UPSTREAM_PORT = 3101; // Avoid conflict with other tests
const GATEWAY_PORT = 4101;
const TEST_TIMEOUT_MS = 30_000;

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

/** Send an HTTP POST with JSON body to a local endpoint. */
function httpPost(
  port: number,
  urlPath: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const json = JSON.stringify(body);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(json),
          ...headers,
        },
        timeout: 10_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode!,
            body: Buffer.concat(chunks).toString('utf-8'),
            headers: res.headers,
          });
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('HTTP request timed out'));
    });
    req.write(json);
    req.end();
  });
}

/** Send an HTTP GET to a local endpoint. */
function httpGet(
  port: number,
  urlPath: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path: urlPath, method: 'GET', timeout: 5_000 },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode!, body: Buffer.concat(chunks).toString('utf-8') }),
        );
      },
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('HTTP request timed out'));
    });
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function testGateway(): Promise<void> {
  console.log('=== HTTP Gateway E2E Test ===\n');

  // Create a temp receipts directory
  const receiptsDir = path.join(os.tmpdir(), `bolyra-receipts-${Date.now()}`);
  fs.mkdirSync(receiptsDir, { recursive: true });

  // Create a temp test file for read_file
  const tmpFile = path.join(os.tmpdir(), `bolyra-gw-test-${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, 'Gateway test content!', 'utf8');

  let upstream: http.Server | null = null;
  let gateway: http.Server | null = null;

  try {
    // Start upstream MCP server
    console.log(`Starting upstream MCP server on port ${UPSTREAM_PORT}...`);
    upstream = startHttp(UPSTREAM_PORT);
    await sleep(500);

    // Start gateway in dev mode
    console.log(`Starting gateway on port ${GATEWAY_PORT} (dev mode)...`);
    const config = loadConfig({
      target: `http://127.0.0.1:${UPSTREAM_PORT}`,
      port: GATEWAY_PORT,
      dev: true,
      receiptDir: receiptsDir,
    });

    gateway = createGatewayProxy({
      config,
      receiptWriter: createReceiptWriter(config.receipts),
      nonceStore: new MemoryNonceStore(),
    });

    await new Promise<void>((resolve) => {
      gateway!.listen(GATEWAY_PORT, () => {
        console.log(`  Gateway listening on port ${GATEWAY_PORT}`);
        resolve();
      });
    });

    // Test 1: Health endpoint
    console.log('\n[Test 1] Health endpoint...');
    const healthResp = await httpGet(GATEWAY_PORT, '/healthz');
    assert.strictEqual(healthResp.status, 200, 'health should return 200');
    console.log('  PASS: /healthz returned 200');

    // Test 2: Initialize (auth-exempt)
    console.log('\n[Test 2] Initialize (auth-exempt)...');
    const initResp = await httpPost(GATEWAY_PORT, '/mcp', {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '0.1.0' },
      },
    });
    assert.strictEqual(initResp.status, 200, 'initialize should return 200');
    const initBody = JSON.parse(initResp.body) as JsonRpcResponse;
    assert.ok(initBody.result, 'initialize should have a result');
    console.log('  PASS: initialize passed through without auth');

    // Test 3: tools/call without Authorization (should be 401)
    console.log('\n[Test 3] tools/call without auth...');
    const noAuthResp = await httpPost(GATEWAY_PORT, '/mcp', {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: tmpFile } },
    });
    assert.strictEqual(noAuthResp.status, 401, 'unauthenticated tools/call should return 401');
    const noAuthBody = JSON.parse(noAuthResp.body) as JsonRpcResponse;
    assert.ok(noAuthBody.error, 'should have error');
    assert.ok(
      noAuthBody.error!.message.includes('Bolyra auth required'),
      'error should mention Bolyra auth',
    );
    // Check WWW-Authenticate header
    assert.ok(
      noAuthResp.headers['www-authenticate']?.includes('Bolyra'),
      'should have WWW-Authenticate: Bolyra header',
    );
    console.log('  PASS: 401 with WWW-Authenticate: Bolyra');

    // Test 4: tools/call with valid dev-mode Authorization
    console.log('\n[Test 4] tools/call with dev-mode auth...');

    // Generate a dev-mode proof bundle
    const human = await createHumanIdentity(0x1234n);
    const credential = await createAgentCredential(
      12345n,
      0x0102030405060708090a0b0c0d0e0f1011121314151617181920212223242526n,
      [Permission.READ_DATA],
      4_102_444_800n, // 2100-01-01
    );

    const auth = await attachBolyraProof(human, credential, { devMode: true });

    const authResp = await httpPost(
      GATEWAY_PORT,
      '/mcp',
      {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'read_file', arguments: { path: tmpFile } },
      },
      auth.headers,
    );

    assert.strictEqual(authResp.status, 200, `authenticated tools/call should return 200, got ${authResp.status}: ${authResp.body}`);
    const authBody = JSON.parse(authResp.body) as JsonRpcResponse;
    assert.ok(authBody.result, 'should have result');
    const resultContent = authBody.result as { content: Array<{ type: string; text: string }> };
    assert.ok(resultContent.content, 'should have content array');
    assert.ok(
      resultContent.content[0]?.text.includes('Gateway test content'),
      'should return file content',
    );
    console.log('  PASS: authenticated tools/call returned file content');

    // Test 5: Check receipts (gateway uses day-rotated subdirectories)
    console.log('\n[Test 5] Checking receipts directory...');
    await sleep(500); // Give receipt writer a moment (fire-and-forget via setImmediate)
    const dateDirs = fs.readdirSync(receiptsDir).filter((d) => {
      const full = path.join(receiptsDir, d);
      return fs.statSync(full).isDirectory();
    });
    assert.ok(dateDirs.length > 0, 'should have at least one date subdirectory in receipts');
    const dateDir = path.join(receiptsDir, dateDirs[0]);
    const receiptFiles = fs.readdirSync(dateDir).filter((f) => f.endsWith('.json'));
    console.log(`  Found ${receiptFiles.length} receipt file(s) in ${dateDir}`);
    assert.ok(receiptFiles.length > 0, 'should have at least one receipt file');
    // Read one receipt to verify it's valid JSON
    const receiptContent = fs.readFileSync(path.join(dateDir, receiptFiles[0]), 'utf8');
    const receipt = JSON.parse(receiptContent);
    assert.ok(receipt.decision || receipt.payload, 'receipt should have decision or payload field');
    console.log(`  PASS: ${receiptFiles.length} receipt(s) found and valid`);

    // Test 6: tools/list with auth (non-exempt method -- needs fresh proof)
    console.log('\n[Test 6] tools/list with auth...');
    // Wait 1.1s so dev-mode nonce (unix seconds) is fresh
    await sleep(1100);
    // Generate a fresh proof (nonce replay protection rejects reused nonces)
    const auth2 = await attachBolyraProof(human, credential, { devMode: true });
    const listResp = await httpPost(
      GATEWAY_PORT,
      '/mcp',
      { jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} },
      auth2.headers,
    );
    assert.strictEqual(listResp.status, 200, `tools/list with auth should return 200, got ${listResp.status}: ${listResp.body}`);
    const listBody = JSON.parse(listResp.body) as JsonRpcResponse;
    assert.ok(listBody.result, 'tools/list should have result');
    const tools = (listBody.result as { tools: Array<{ name: string }> }).tools;
    assert.ok(tools.length >= 3, 'should list at least 3 tools');
    console.log(`  PASS: tools/list returned ${tools.length} tools`);

    console.log('\n=== All HTTP Gateway Tests Passed ===\n');
  } finally {
    // Cleanup
    if (gateway) {
      await new Promise<void>((resolve) => gateway!.close(() => resolve()));
    }
    if (upstream) {
      await new Promise<void>((resolve) => upstream!.close(() => resolve()));
    }
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // ignore
    }
    try {
      fs.rmSync(receiptsDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

// Run with timeout
const timeout = setTimeout(() => {
  console.error('ERROR: Test timed out');
  process.exit(1);
}, TEST_TIMEOUT_MS);

testGateway()
  .then(() => {
    clearTimeout(timeout);
    process.exit(0);
  })
  .catch((err) => {
    clearTimeout(timeout);
    console.error('\nTEST FAILED:', err);
    process.exit(1);
  });
