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

  it('creates four tools', () => {
    expect(Object.keys(tools)).toEqual(
      expect.arrayContaining([
        'bolyra_authenticate',
        'bolyra_delegate',
        'bolyra_check_permissions',
        'bolyra_credential_info',
      ]),
    );
    expect(Object.keys(tools)).toHaveLength(4);
  });

  it('all tools have description and parameters', () => {
    for (const [name, t] of Object.entries(tools)) {
      expect(t.description).toBeTruthy();
      expect(t.parameters).toBeDefined();
    }
  });

  it('all tools have execute functions', () => {
    for (const [name, t] of Object.entries(tools)) {
      expect(typeof t.execute).toBe('function');
    }
  });

  describe('bolyra_authenticate', () => {
    it('returns authenticated status in dev mode', async () => {
      const result = await tools.bolyra_authenticate.execute!(
        {},
        { toolCallId: 'test-1', messages: [], abortSignal: undefined },
      );
      expect(result.status).toBe('authenticated');
      expect(result.mode).toBe('dev');
      expect(result.bundle).toBeTruthy();
      expect(result.did).toContain('did:bolyra:dev:');
    });

    it('accepts an optional nonce', async () => {
      const result = await tools.bolyra_authenticate.execute!(
        { nonce: '12345' },
        { toolCallId: 'test-2', messages: [], abortSignal: undefined },
      );
      expect(result.status).toBe('authenticated');
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
