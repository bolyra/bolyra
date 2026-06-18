import { injectBolyraHeaders, computeHmac, verifyHmac } from '../src/headers';
import type { BolyraAuthContext } from '@bolyra/mcp';

function makeAuthCtx(overrides: Partial<BolyraAuthContext> = {}): BolyraAuthContext {
  return {
    verified: true,
    score: 90,
    did: 'did:bolyra:base-sepolia:abcdef0123456789',
    permissionBitmask: 0b11n,
    warnings: [],
    chainDepth: 0,
    effectiveCommitment: '12345678',
    ...overrides,
  };
}

describe('header injection', () => {
  describe('injectBolyraHeaders', () => {
    it('produces correct header names and values', () => {
      const ctx = makeAuthCtx();
      const headers = injectBolyraHeaders(ctx);

      expect(headers['X-Bolyra-Verified']).toBe('true');
      expect(headers['X-Bolyra-DID']).toBe('did:bolyra:base-sepolia:abcdef0123456789');
      expect(headers['X-Bolyra-Score']).toBe('90');
      expect(headers['X-Bolyra-Permissions']).toBe('3');
      expect(headers['X-Bolyra-Chain-Depth']).toBe('0');
    });

    it('includes receipt ID when provided', () => {
      const ctx = makeAuthCtx();
      const headers = injectBolyraHeaders(ctx, 'receipt-123');
      expect(headers['X-Bolyra-Receipt-ID']).toBe('receipt-123');
    });

    it('omits receipt ID when not provided', () => {
      const ctx = makeAuthCtx();
      const headers = injectBolyraHeaders(ctx);
      expect(headers['X-Bolyra-Receipt-ID']).toBeUndefined();
    });

    it('handles delegation chain depth', () => {
      const ctx = makeAuthCtx({ chainDepth: 2 });
      const headers = injectBolyraHeaders(ctx);
      expect(headers['X-Bolyra-Chain-Depth']).toBe('2');
    });
  });

  describe('HMAC', () => {
    const secret = 'deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567';

    it('computeHmac produces a hex string', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac = computeHmac(headers, secret);
      expect(typeof mac).toBe('string');
      expect(mac).toMatch(/^[a-f0-9]{64}$/);
    });

    it('verifyHmac returns true for valid HMAC', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac = computeHmac(headers, secret);
      expect(verifyHmac(headers, secret, mac)).toBe(true);
    });

    it('verifyHmac returns false for tampered headers', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac = computeHmac(headers, secret);
      headers['X-Bolyra-Score'] = '100'; // tamper
      expect(verifyHmac(headers, secret, mac)).toBe(false);
    });

    it('verifyHmac returns false for wrong secret', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac = computeHmac(headers, secret);
      const wrongSecret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      expect(verifyHmac(headers, wrongSecret, mac)).toBe(false);
    });

    it('HMAC is deterministic for same inputs', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac1 = computeHmac(headers, secret);
      const mac2 = computeHmac(headers, secret);
      expect(mac1).toBe(mac2);
    });

    it('excludes X-Bolyra-HMAC from computation', () => {
      const headers = injectBolyraHeaders(makeAuthCtx());
      const mac1 = computeHmac(headers, secret);
      headers['X-Bolyra-HMAC'] = 'should-be-ignored';
      const mac2 = computeHmac(headers, secret);
      expect(mac1).toBe(mac2);
    });
  });
});
