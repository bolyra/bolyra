/**
 * RedisNonceStore unit tests.
 *
 * Mocks the `redis` module to avoid requiring a running Redis instance.
 * Tests verify correct SET NX EX calls, key prefixing, return values,
 * and graceful shutdown.
 */

// Mock redis before importing RedisNonceStore
const mockSet = jest.fn();
const mockQuit = jest.fn();
const mockConnect = jest.fn();
const mockOn = jest.fn();

jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    set: mockSet,
    quit: mockQuit,
    connect: mockConnect.mockResolvedValue(undefined),
    on: mockOn,
  })),
}));

import { RedisNonceStore } from '../src/redis-nonce-store';

describe('RedisNonceStore', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockConnect.mockResolvedValue(undefined);
  });

  describe('constructor', () => {
    it('creates a Redis client with the given URL', () => {
      const { createClient } = require('redis');
      new RedisNonceStore({ url: 'redis://localhost:6379' });

      expect(createClient).toHaveBeenCalledWith(
        expect.objectContaining({
          url: 'redis://localhost:6379',
        }),
      );
    });

    it('registers an error handler', () => {
      new RedisNonceStore({ url: 'redis://localhost:6379' });
      expect(mockOn).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('initiates connection', () => {
      new RedisNonceStore({ url: 'redis://localhost:6379' });
      expect(mockConnect).toHaveBeenCalled();
    });
  });

  describe('markIfFresh', () => {
    it('returns true when SET NX EX returns OK (fresh nonce)', async () => {
      mockSet.mockResolvedValue('OK');
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      const result = await store.markIfFresh('nonce-abc', 300);

      expect(result).toBe(true);
      expect(mockSet).toHaveBeenCalledWith('bolyra:nonce:nonce-abc', '1', {
        NX: true,
        EX: 300,
      });
    });

    it('returns false when SET NX EX returns null (replayed nonce)', async () => {
      mockSet.mockResolvedValue(null);
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      const result = await store.markIfFresh('nonce-abc', 300);

      expect(result).toBe(false);
    });

    it('applies custom key prefix', async () => {
      mockSet.mockResolvedValue('OK');
      const store = new RedisNonceStore({
        url: 'redis://localhost:6379',
        keyPrefix: 'myapp:nonces:',
      });

      await store.markIfFresh('test-nonce', 60);

      expect(mockSet).toHaveBeenCalledWith('myapp:nonces:test-nonce', '1', {
        NX: true,
        EX: 60,
      });
    });

    it('uses default prefix when none specified', async () => {
      mockSet.mockResolvedValue('OK');
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      await store.markIfFresh('n1', 120);

      expect(mockSet).toHaveBeenCalledWith('bolyra:nonce:n1', '1', {
        NX: true,
        EX: 120,
      });
    });

    it('passes the TTL from the ttlSeconds argument', async () => {
      mockSet.mockResolvedValue('OK');
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      await store.markIfFresh('nonce-ttl', 600);

      expect(mockSet).toHaveBeenCalledWith(
        expect.any(String),
        '1',
        expect.objectContaining({ EX: 600 }),
      );
    });

    it('rejects (fail-closed) when Redis throws', async () => {
      mockSet.mockRejectedValue(new Error('Connection refused'));
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      await expect(store.markIfFresh('nonce-fail', 300)).rejects.toThrow(
        'Connection refused',
      );
    });

    it('rejects (fail-closed) when connection fails', async () => {
      mockConnect.mockRejectedValue(new Error('ECONNREFUSED'));
      const store = new RedisNonceStore({ url: 'redis://bad-host:6379' });

      await expect(store.markIfFresh('nonce-fail', 300)).rejects.toThrow();
    });
  });

  describe('close', () => {
    it('calls client.quit()', async () => {
      mockQuit.mockResolvedValue(undefined);
      const store = new RedisNonceStore({ url: 'redis://localhost:6379' });

      await store.close();

      expect(mockQuit).toHaveBeenCalled();
    });
  });
});
