/**
 * Tests for bolyraAuthMiddleware() — server-side verification.
 */

import { bolyraAuthMiddleware } from '../src/server-middleware';
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof } from '@bolyra/mcp';

describe('bolyraAuthMiddleware', () => {
  it('returns a verifier with verify and verifyHeader methods', () => {
    const verifier = bolyraAuthMiddleware({ devMode: true });
    expect(typeof verifier.verify).toBe('function');
    expect(typeof verifier.verifyHeader).toBe('function');
  });

  it('rejects request with missing Authorization header', async () => {
    const verifier = bolyraAuthMiddleware({ devMode: true });
    const req = new Request('http://localhost/api/tool', {
      method: 'POST',
    });
    const result = await verifier.verify(req);
    expect(result.verified).toBe(false);
    expect(result.reason).toContain('Missing Authorization header');
  });

  it('rejects request with invalid Authorization header', async () => {
    const verifier = bolyraAuthMiddleware({ devMode: true });
    const req = new Request('http://localhost/api/tool', {
      method: 'POST',
      headers: { Authorization: 'Bearer invalid-token' },
    });
    const result = await verifier.verify(req);
    expect(result.verified).toBe(false);
    expect(result.reason).toContain('Invalid Authorization header');
  });

  it('rejects request with malformed base64 in Bolyra header', async () => {
    const verifier = bolyraAuthMiddleware({ devMode: true });
    const req = new Request('http://localhost/api/tool', {
      method: 'POST',
      headers: { Authorization: 'Bolyra not-valid-base64!!!' },
    });
    const result = await verifier.verify(req);
    expect(result.verified).toBe(false);
  });

  it('verifies a valid dev-mode proof bundle', async () => {
    const devIds = await createDevIdentities();
    const auth = await attachBolyraProof(devIds.human, devIds.agent, {
      devMode: true,
    });

    const verifier = bolyraAuthMiddleware({ devMode: true });
    const req = new Request('http://localhost/api/tool', {
      method: 'POST',
      headers: auth.headers,
    });
    const result = await verifier.verify(req);
    expect(result.verified).toBe(true);
    expect(result.context).toBeDefined();
    expect(result.context!.did).toContain('did:bolyra:');
  });

  it('verifies via verifyHeader with raw header string', async () => {
    const devIds = await createDevIdentities();
    const auth = await attachBolyraProof(devIds.human, devIds.agent, {
      devMode: true,
    });

    const verifier = bolyraAuthMiddleware({ devMode: true });
    const result = await verifier.verifyHeader(auth.headers.Authorization);
    expect(result.verified).toBe(true);
  });

  it('rejects dev bundle when devMode is false (production server)', async () => {
    const devIds = await createDevIdentities();
    const auth = await attachBolyraProof(devIds.human, devIds.agent, {
      devMode: true,
    });

    // Production server should reject dev bundles
    const verifier = bolyraAuthMiddleware({
      devMode: false,
      resolveCredential: async () => null,
    });
    const result = await verifier.verifyHeader(auth.headers.Authorization);
    expect(result.verified).toBe(false);
  });

  it('checks per-tool policy when tool name is provided', async () => {
    const devIds = await createDevIdentities();
    // Dev identities have all permissions (0b11111111)
    const auth = await attachBolyraProof(devIds.human, devIds.agent, {
      devMode: true,
    });

    const verifier = bolyraAuthMiddleware({
      devMode: true,
      toolPolicy: {
        'read_file': { requireBitmask: 1 }, // READ_DATA bit
      },
    });

    const result = await verifier.verifyHeader(
      auth.headers.Authorization,
      'read_file',
    );
    expect(result.verified).toBe(true);
  });
});
