import type { NonceStore } from './types';

/**
 * In-memory nonce store with automatic TTL cleanup.
 * Suitable for single-process MCP servers. For multi-process
 * deployments, implement NonceStore against Redis/DB.
 */
export class MemoryNonceStore implements NonceStore {
  private used = new Map<string, number>(); // nonce -> expiry timestamp (ms)

  async markIfFresh(nonce: string, ttlSeconds: number): Promise<boolean> {
    this.cleanup();
    if (this.used.has(nonce)) return false;
    this.used.set(nonce, Date.now() + ttlSeconds * 1000);
    return true;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.used) {
      if (expiry <= now) this.used.delete(nonce);
    }
  }
}
