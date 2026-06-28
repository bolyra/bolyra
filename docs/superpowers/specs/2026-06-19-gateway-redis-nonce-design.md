# Redis NonceStore for @bolyra/gateway v0.2.0 -- Design Spec

**Date:** 2026-06-19
**Author:** Viswa + Claude Opus 4.6
**Status:** Draft
**PDLC:** `pdlc-2026-06-19-gateway-redis-nonce`
**Package:** `@bolyra/gateway` (0.1.0 -> 0.2.0)

## Problem

The gateway currently uses `MemoryNonceStore` from `@bolyra/mcp` for replay protection. This has two production-readiness gaps:

1. **No persistence.** Nonces are lost on process restart. An attacker can replay a proof bundle captured before the restart against the restarted gateway.
2. **No sharing.** In multi-instance deployments (e.g., behind a load balancer), each gateway replica maintains its own nonce set. A proof verified by instance A can be replayed against instance B.

Both were explicitly deferred during v0.1.0 (noted in config validation: `"nonce.store" must be "memory" (Redis adapter deferred to v0.2)`).

## Solution

Add a `RedisNonceStore` class that implements the existing `NonceStore` interface from `@bolyra/mcp`, backed by Redis. The implementation lives in `@bolyra/gateway` (not `@bolyra/mcp`) because:

- The gateway is the primary consumer that needs multi-instance replay protection
- Keeping Redis as an optional dependency of the gateway avoids burdening `@bolyra/mcp` with a Redis peer dep
- Library users of `@bolyra/mcp` who want Redis can import `RedisNonceStore` from `@bolyra/gateway`

### NonceStore Interface (existing, no changes)

```typescript
// From @bolyra/mcp/src/types.ts — DO NOT MODIFY
export interface NonceStore {
  markIfFresh(nonce: string, ttlSeconds: number): Promise<boolean>;
}
```

### RedisNonceStore Implementation

```typescript
// New file: integrations/gateway/src/redis-nonce-store.ts
import { createClient, type RedisClientType } from 'redis';
import type { NonceStore } from '@bolyra/mcp';

export interface RedisNonceStoreOptions {
  /** Redis connection URL (e.g., redis://localhost:6379). */
  url: string;
  /** Key prefix to namespace nonces (default: "bolyra:nonce:"). */
  keyPrefix?: string;
  /** Connection timeout in ms (default: 5000). */
  connectTimeout?: number;
}

export class RedisNonceStore implements NonceStore {
  private client: RedisClientType;
  private prefix: string;
  private ready: Promise<void>;

  constructor(options: RedisNonceStoreOptions) {
    this.prefix = options.keyPrefix ?? 'bolyra:nonce:';
    this.client = createClient({
      url: options.url,
      socket: {
        connectTimeout: options.connectTimeout ?? 5000,
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
      },
    });
    this.client.on('error', (err) => {
      console.error('[gateway] Redis nonce store error:', err.message);
    });
    this.ready = this.client.connect();
  }

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
```

**Key design decisions:**

1. **`SET NX EX` is atomic.** A single Redis command handles both the existence check and the TTL set. No race conditions between check and mark. This is the canonical Redis pattern for distributed locks/deduplication.

2. **TTL handles cleanup.** Redis expires keys automatically. No background sweep needed (unlike `MemoryNonceStore.cleanup()`). The TTL matches `maxProofAge` from the gateway config.

3. **`redis` npm package (v4+).** The official Node.js Redis client. Well-maintained, TypeScript-native, supports Sentinel/Cluster via URL schemes. Added as a regular dependency of `@bolyra/gateway`, not a peer dep — the gateway is an application package, not a library that needs to be dependency-light.

4. **Key prefix.** Defaults to `bolyra:nonce:` to avoid collisions with other Redis users on shared instances. Configurable for multi-tenant or multi-environment setups.

5. **Lazy connection.** The constructor initiates connection but `markIfFresh` awaits the `ready` promise. First call may have connection latency; subsequent calls are immediate.

6. **Reconnection.** Uses the `redis` client's built-in reconnect strategy with exponential backoff capped at 3s. If Redis is down, `markIfFresh` will reject (not silently pass), which causes the gateway to return 500 — fail closed, not fail open.

## Configuration

### gateway.yaml Changes

```yaml
# Before (v0.1.0 — only option)
nonce:
  store: memory
  maxProofAge: 300

# After (v0.2.0 — Redis opt-in)
nonce:
  store: redis
  maxProofAge: 300
  redis:
    url: ${REDIS_URL}           # required when store=redis
    keyPrefix: "bolyra:nonce:"  # optional, default shown
```

### Type Changes

```typescript
// types.ts — NonceConfig updated
export interface NonceConfig {
  store: 'memory' | 'redis';
  maxProofAge?: number;
  redis?: {
    url: string;
    keyPrefix?: string;
    connectTimeout?: number;
  };
}
```

### Config Validation Changes

The current validation rejects anything other than `store: 'memory'`. Update to:

- `store: 'memory'` — valid, no additional config required
- `store: 'redis'` — valid, but `nonce.redis.url` becomes required
- `store: 'redis'` without `nonce.redis.url` — validation error
- `nonce.redis.url` containing unresolved `${...}` — validation error (catches missing env vars)
- Any other `store` value — validation error

### CLI Changes

The CLI (`src/cli.ts`) currently hardcodes `new MemoryNonceStore()`. Update to read `config.nonce.store` and instantiate the appropriate store:

```typescript
// cli.ts — nonce store factory
const nonceStore = config.nonce.store === 'redis'
  ? new RedisNonceStore({
      url: config.nonce.redis!.url,
      keyPrefix: config.nonce.redis?.keyPrefix,
      connectTimeout: config.nonce.redis?.connectTimeout,
    })
  : new MemoryNonceStore();
```

Add graceful shutdown of `RedisNonceStore.close()` to the SIGINT/SIGTERM handler.

### Banner Update

Add nonce store info to the startup banner:

```
@bolyra/gateway v0.2.0
  Mode:     production
  Target:   http://localhost:3000/mcp
  Port:     4100
  Nonce:    redis (redis://localhost:6379)    <-- NEW
  Receipts: ./receipts/ (file)
  Network:  base-sepolia
```

## Exports

`RedisNonceStore` and `RedisNonceStoreOptions` are exported from `@bolyra/gateway`'s public API (`src/index.ts`). This lets library users who embed the middleware create their own Redis nonce store:

```typescript
import { createGatewayMiddleware, RedisNonceStore } from '@bolyra/gateway';
const store = new RedisNonceStore({ url: 'redis://localhost:6379' });
const middleware = createGatewayMiddleware({ config, nonceStore: store });
```

## Testing Strategy

### Unit Tests (no Redis required)

1. **RedisNonceStore with mock** — Mock the `redis` client to verify:
   - `markIfFresh` calls `SET` with correct key, NX, and EX args
   - Returns `true` when SET returns `'OK'`
   - Returns `false` when SET returns `null`
   - Key prefix is applied correctly
   - `close()` calls `client.quit()`

2. **Config validation** — Test that:
   - `store: 'redis'` without `redis.url` throws `ConfigValidationError`
   - `store: 'redis'` with `redis.url` passes validation
   - `store: 'memory'` continues to work (regression)
   - Unknown `store` values are rejected

3. **CLI nonce store factory** — Test that config drives store selection

### Integration Tests (Redis required, skipped in CI without Redis)

4. **Real Redis round-trip** — Use `testcontainers` or skip if no Redis:
   - First `markIfFresh("nonce-1", 60)` returns `true`
   - Second `markIfFresh("nonce-1", 60)` returns `false`
   - After TTL expires, `markIfFresh("nonce-1", 1)` returns `true` again (wait 2s)
   - Two `RedisNonceStore` instances sharing the same Redis see each other's nonces

## Fail-Closed Behavior

If Redis is unreachable:

- **On startup:** `RedisNonceStore` constructor initiates connection. If Redis is down, the `ready` promise will reject on first `markIfFresh` call. The gateway will return HTTP 500 (internal error), not 200 (pass through). This is fail-closed.
- **During operation:** If Redis disconnects mid-operation, the `redis` client will attempt reconnection. Calls to `markIfFresh` during disconnection will reject, producing 500s. Once Redis recovers, the client reconnects automatically and operations resume.
- **Rationale:** Failing open (allowing all requests when Redis is down) would defeat the purpose of replay protection. Operators should monitor Redis availability as a critical dependency.

## Backward Compatibility

- **Default is unchanged.** `nonce.store` defaults to `'memory'`. Existing `gateway.yaml` files without a `nonce` section continue to work identically.
- **No changes to @bolyra/mcp.** The `NonceStore` interface and `MemoryNonceStore` are untouched.
- **No changes to library API.** `GatewayMiddlewareOptions.nonceStore` still accepts any `NonceStore` implementation. `RedisNonceStore` is a new addition to the export surface, not a replacement.

## Version Bump

- `@bolyra/gateway`: `0.1.0` -> `0.2.0` (minor — new feature, backward compatible)
- No other packages change.

## Dependencies Added

| Package | Version | Type | Size Impact |
|---------|---------|------|-------------|
| `redis` | `^4.7.0` | runtime | ~150KB (tree-shaken) |

The `redis` package has zero native dependencies. It is pure JS/TS. No `node-gyp` build step.

## Files Changed (Expected)

| File | Change |
|------|--------|
| `integrations/gateway/src/redis-nonce-store.ts` | NEW — RedisNonceStore class |
| `integrations/gateway/src/types.ts` | MODIFY — update NonceConfig type |
| `integrations/gateway/src/config.ts` | MODIFY — update validation for redis store |
| `integrations/gateway/src/cli.ts` | MODIFY — nonce store factory + shutdown |
| `integrations/gateway/src/index.ts` | MODIFY — export RedisNonceStore |
| `integrations/gateway/package.json` | MODIFY — add redis dep, bump to 0.2.0 |
| `integrations/gateway/test/redis-nonce-store.test.ts` | NEW — unit tests |
| `integrations/gateway/test/config.test.ts` | MODIFY — add redis validation tests |
| `integrations/gateway/README.md` | MODIFY — document Redis config |

## Security Considerations

This change touches the **nonce replay protection surface**, which is security-critical:

1. **Atomicity.** `SET NX EX` is a single Redis command. No TOCTOU race between checking and marking a nonce. This is strictly stronger than `MemoryNonceStore`, which has a (theoretical) race in concurrent async contexts.

2. **Fail-closed.** Redis unavailability causes 500, not pass-through. Documented above.

3. **No credential storage.** Redis stores only nonce strings (opaque hex/base64) with TTLs. No proof bundles, no auth contexts, no PII.

4. **Key prefix isolation.** Prevents cross-contamination on shared Redis instances. The prefix is configurable but defaults to `bolyra:nonce:`.

5. **Connection string in config.** The `redis.url` supports `${REDIS_URL}` env var substitution (already handled by the config loader's `substituteEnvVars`). Operators should not hardcode credentials in `gateway.yaml`.

6. **TLS support.** The `redis` client supports `rediss://` URLs for TLS connections. No gateway code changes needed — this is handled by the client library.

## Out of Scope

- Redis Sentinel / Cluster — supported by the `redis` client library via URL schemes (`redis-sentinel://`, `redis+cluster://`), but not explicitly tested or documented in v0.2.0
- Custom nonce store factory plugin system — library users can already pass any `NonceStore` implementation
- Metrics / observability hooks for nonce store operations — deferred to a future observability pass
- Migration tool for in-flight nonces from memory to Redis on upgrade — nonces are short-lived (5min default TTL), so a restart gap is acceptable
