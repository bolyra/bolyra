/**
 * @bolyra/gateway — Redis-backed NonceStore.
 *
 * Uses Redis SET with NX + EX for atomic mark-if-fresh. A single Redis
 * command handles both the existence check and TTL set — no race conditions.
 *
 * Fail-closed: if Redis is unreachable, markIfFresh rejects (throws),
 * causing the gateway to return 500, never pass through.
 */

import { createClient, type RedisClientType } from 'redis';
import type { NonceStore } from '@bolyra/mcp';

/** Options for creating a RedisNonceStore. */
export interface RedisNonceStoreOptions {
  /** Redis connection URL (e.g., redis://localhost:6379). */
  url: string;
  /** Key prefix to namespace nonces (default: "bolyra:nonce:"). */
  keyPrefix?: string;
  /** Connection timeout in ms (default: 5000). */
  connectTimeout?: number;
}

/**
 * Redis-backed nonce store for multi-instance gateway deployments.
 *
 * Each nonce is stored as a Redis key with a TTL matching maxProofAge.
 * Redis handles expiration automatically — no background sweep needed.
 */
export class RedisNonceStore implements NonceStore {
  private client: RedisClientType;
  private prefix: string;
  private ready: Promise<unknown>;

  constructor(options: RedisNonceStoreOptions) {
    this.prefix = options.keyPrefix ?? 'bolyra:nonce:';
    this.client = createClient({
      url: options.url,
      socket: {
        connectTimeout: options.connectTimeout ?? 5000,
        reconnectStrategy: (retries: number) => Math.min(retries * 100, 3000),
      },
    });
    this.client.on('error', (err: Error) => {
      console.error('[gateway] Redis nonce store error:', err.message);
    });
    this.ready = this.client.connect();
  }

  /**
   * Mark a nonce as seen if it has not been seen before.
   *
   * Returns true if the nonce is fresh (first time seen), false if replayed.
   * Uses SET NX EX — a single atomic Redis command.
   *
   * Throws if Redis is unreachable (fail-closed).
   */
  async markIfFresh(nonce: string, ttlSeconds: number): Promise<boolean> {
    await this.ready;
    const key = `${this.prefix}${nonce}`;
    // SET key "1" NX EX ttlSeconds — returns 'OK' if set, null if key exists
    const result = await this.client.set(key, '1', { NX: true, EX: ttlSeconds });
    return result === 'OK';
  }

  /** Graceful shutdown — disconnect from Redis. */
  async close(): Promise<void> {
    await this.client.quit();
  }
}
