/**
 * Tests for createBolyraTools() — Vercel AI SDK tool definitions.
 */

import { createBolyraTools } from '../src/tools';
import { createDevIdentities } from '@bolyra/sdk';

describe('createBolyraTools', () => {
  let credential: Awaited<ReturnType<typeof createDevIdentities>>['agent'];
  let tools: ReturnType<typeof createBolyraTools>;

  beforeAll(async () => {
    const devIds = await createDevIdentities();
    credential = devIds.agent;
    tools = createBolyraTools({
      credential,
      devMode: true,
    });
  });

  const toolNames = [
    'bolyra_authenticate',
    'bolyra_delegate',
    'bolyra_check_permissions',
    'bolyra_credential_info',
  ] as const;

  it('creates four tools plus accessors', () => {
    expect(Object.keys(tools)).toEqual(
      expect.arrayContaining([...toolNames]),
    );
    // 4 tools + getLastBundle + getLastAuthHeader
    expect(Object.keys(tools)).toHaveLength(6);
    expect(typeof tools.getLastBundle).toBe('function');
    expect(typeof tools.getLastAuthHeader).toBe('function');
  });

  it('all tools have description and parameters', () => {
    for (const name of toolNames) {
      const t = tools[name];
      expect(t.description).toBeTruthy();
      expect(t.parameters).toBeDefined();
    }
  });

  it('all tools have execute functions', () => {
    for (const name of toolNames) {
      const t = tools[name];
      expect(typeof t.execute).toBe('function');
    }
  });

  describe('bolyra_authenticate', () => {
    it('returns authenticated status in dev mode', async () => {
      const result = await tools.bolyra_authenticate.execute!(
        {},
        { toolCallId: 'test-1', messages: [], abortSignal: undefined },
      );
      expect(result.authenticated).toBe(true);
      expect(result.mode).toBe('dev');
      // C2: bundle must NOT be in tool output
      expect(result.bundle).toBeUndefined();
      expect(result.did).toContain('did:bolyra:dev:');
      expect(result.expiresAt).toBeTruthy();
      // Bundle should be accessible via accessor
      expect(tools.getLastBundle()).not.toBeNull();
      expect(tools.getLastAuthHeader()).toContain('Bolyra ');
    });

    it('accepts an optional nonce', async () => {
      const result = await tools.bolyra_authenticate.execute!(
        { nonce: '12345' },
        { toolCallId: 'test-2', messages: [], abortSignal: undefined },
      );
      expect(result.authenticated).toBe(true);
    });
  });

  describe('bolyra_delegate', () => {
    it('delegates with narrowed permissions in dev mode', async () => {
      const result = await tools.bolyra_delegate.execute!(
        { permissions: 0b11, ttlSeconds: 3600 },
        { toolCallId: 'test-3', messages: [], abortSignal: undefined },
      );
      expect(result.status).toBe('delegated');
      expect(result.mode).toBe('dev');
    });

    it('rejects escalation attempt', async () => {
      // Create tools with a credential that only has READ_DATA
      const devIds = await createDevIdentities({ permissionBitmask: 0b01n });
      const restrictedTools = createBolyraTools({
        credential: devIds.agent,
        devMode: true,
      });

      const result = await restrictedTools.bolyra_delegate.execute!(
        { permissions: 0b11111111, ttlSeconds: 3600 },
        { toolCallId: 'test-4', messages: [], abortSignal: undefined },
      );
      expect(result.status).toBe('error');
      expect(result.reason).toContain('Cannot escalate');
    });
  });

  describe('bolyra_check_permissions', () => {
    it('reports READ_DATA as granted for full-permission credential', async () => {
      const result = await tools.bolyra_check_permissions.execute!(
        { permission: 'READ_DATA' },
        { toolCallId: 'test-5', messages: [], abortSignal: undefined },
      );
      expect(result.granted).toBe(true);
      expect(result.permission).toBe('READ_DATA');
    });

    it('is case-insensitive', async () => {
      const result = await tools.bolyra_check_permissions.execute!(
        { permission: 'read_data' },
        { toolCallId: 'test-6', messages: [], abortSignal: undefined },
      );
      expect(result.granted).toBe(true);
    });

    it('returns error for unknown permission', async () => {
      const result = await tools.bolyra_check_permissions.execute!(
        { permission: 'NONEXISTENT' },
        { toolCallId: 'test-7', messages: [], abortSignal: undefined },
      );
      expect(result.status).toBe('error');
      expect(result.reason).toContain('Unknown permission');
    });
  });

  describe('bolyra_credential_info', () => {
    it('returns credential metadata', async () => {
      const result = await tools.bolyra_credential_info.execute!(
        {},
        { toolCallId: 'test-8', messages: [], abortSignal: undefined },
      );
      expect(result.did).toContain('did:bolyra:');
      expect(result.permissions).toEqual(
        expect.arrayContaining(['READ_DATA', 'WRITE_DATA']),
      );
      expect(result.devMode).toBe(true);
      expect(result.expiryDate).toBeTruthy();
    });
  });
});
