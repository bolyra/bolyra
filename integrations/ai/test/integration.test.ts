/**
 * Integration tests — end-to-end with dev mode.
 *
 * Tests the full flow: withBolyraAuth wraps a model, createBolyraTools
 * creates tools, and bolyraAuthMiddleware verifies.
 */

import { withBolyraAuth } from '../src/middleware';
import { bolyraAuthMiddleware } from '../src/server-middleware';
import { createBolyraTools } from '../src/tools';
import {
  encodeBundle,
  decodeBundleFromHeader,
  buildAuthHeader,
  generateNonce,
  buildBolyraHeaders,
} from '../src/utils';
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof } from '@bolyra/mcp';
import type { LanguageModelV1 } from 'ai';

/** Create a minimal mock LanguageModelV1. */
function createMockModel(): LanguageModelV1 {
  return {
    specificationVersion: 'v1',
    provider: 'test-provider',
    modelId: 'test-model',
    defaultObjectGenerationMode: 'json',
    supportsUrl: undefined,
    doGenerate: jest.fn().mockResolvedValue({
      rawCall: { rawPrompt: '', rawSettings: {} },
      finishReason: 'stop' as const,
      usage: { promptTokens: 10, completionTokens: 5 },
      text: 'test response',
    }),
    doStream: jest.fn().mockResolvedValue({
      rawCall: { rawPrompt: '', rawSettings: {} },
      stream: new ReadableStream(),
    }),
  };
}

describe('Integration: utils', () => {
  it('encodeBundle and decodeBundleFromHeader round-trip', async () => {
    const devIds = await createDevIdentities();
    const auth = await attachBolyraProof(devIds.human, devIds.agent, { devMode: true });
    const header = buildAuthHeader(auth.bundle);

    const decoded = decodeBundleFromHeader(header);
    expect(decoded).not.toBeNull();
    expect(decoded!.v).toBe(auth.bundle.v);
    expect(decoded!.nonce).toBe(auth.bundle.nonce);
    expect(decoded!.credentialCommitment).toBe(auth.bundle.credentialCommitment);
    expect(decoded!._dev).toBe(true);
  });

  it('generateNonce produces a bigint with timestamp in upper bits', () => {
    const nonce = generateNonce();
    expect(typeof nonce).toBe('bigint');
    const ts = nonce >> 64n;
    const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
    // Should be within a few seconds of now
    expect(ts).toBeGreaterThanOrEqual(nowSeconds - 5n);
    expect(ts).toBeLessThanOrEqual(nowSeconds + 5n);
  });

  it('buildBolyraHeaders creates expected headers', () => {
    const headers = buildBolyraHeaders({
      did: 'did:bolyra:dev:abc123',
      permissionBitmask: 0b11111111n,
      score: 100,
      chainDepth: 0,
    });
    expect(headers['X-Bolyra-DID']).toBe('did:bolyra:dev:abc123');
    expect(headers['X-Bolyra-Permissions']).toBe('11111111');
    expect(headers['X-Bolyra-Score']).toBe('100');
    expect(headers['X-Bolyra-Chain-Depth']).toBe('0');
  });

  it('decodeBundleFromHeader returns null for non-Bolyra header', () => {
    expect(decodeBundleFromHeader('Bearer abc123')).toBeNull();
  });

  it('decodeBundleFromHeader returns null for malformed base64', () => {
    expect(decodeBundleFromHeader('Bolyra !!invalid!!')).toBeNull();
  });
});

describe('Integration: full auth flow (dev mode)', () => {
  it('client wraps model, server verifies bundle', async () => {
    const devIds = await createDevIdentities();

    // Client side: wrap a model with Bolyra auth
    const model = createMockModel();
    const wrapped = withBolyraAuth(model, {
      credential: devIds.agent,
      devMode: true,
    });
    expect(wrapped.modelId).toBe('bolyra:test-model');

    // Simulate: client generates a proof bundle
    const auth = await attachBolyraProof(devIds.human, devIds.agent, { devMode: true });

    // Server side: verify the bundle
    const verifier = bolyraAuthMiddleware({ devMode: true });
    const req = new Request('http://localhost/api/tool', {
      method: 'POST',
      headers: auth.headers,
    });

    const result = await verifier.verify(req);
    expect(result.verified).toBe(true);
    expect(result.context).toBeDefined();
    expect(result.context!.score).toBeGreaterThanOrEqual(70);
  });

  it('tools can be created and used alongside model', async () => {
    const devIds = await createDevIdentities();

    // Create Bolyra tools
    const bolyraTools = createBolyraTools({
      credential: devIds.agent,
      devMode: true,
    });

    // Verify tool names
    expect(bolyraTools.bolyra_authenticate).toBeDefined();
    expect(bolyraTools.bolyra_credential_info).toBeDefined();

    // Execute authenticate tool
    const authResult = await bolyraTools.bolyra_authenticate.execute!(
      {},
      { toolCallId: 'int-1', messages: [], abortSignal: undefined },
    );
    expect(authResult.status).toBe('authenticated');
    expect(authResult.bundle).toBeTruthy();

    // Execute credential info tool
    const infoResult = await bolyraTools.bolyra_credential_info.execute!(
      {},
      { toolCallId: 'int-2', messages: [], abortSignal: undefined },
    );
    expect(infoResult.did).toContain('did:bolyra:');
    expect(infoResult.permissions.length).toBeGreaterThan(0);
  });

  it('full round-trip: authenticate tool bundle verifies on server', async () => {
    const devIds = await createDevIdentities();

    // Client authenticates via tool
    const bolyraTools = createBolyraTools({
      credential: devIds.agent,
      devMode: true,
    });
    const authResult = await bolyraTools.bolyra_authenticate.execute!(
      {},
      { toolCallId: 'rt-1', messages: [], abortSignal: undefined },
    );
    expect(authResult.status).toBe('authenticated');

    // Decode the bundle from the tool result
    const bundleBase64 = authResult.bundle;
    const bundleJson = Buffer.from(bundleBase64, 'base64').toString('utf8');
    const bundle = JSON.parse(bundleJson);

    // Server verifies
    const header = `Bolyra ${bundleBase64}`;
    const verifier = bolyraAuthMiddleware({ devMode: true });
    const result = await verifier.verifyHeader(header);
    expect(result.verified).toBe(true);
  });
});
