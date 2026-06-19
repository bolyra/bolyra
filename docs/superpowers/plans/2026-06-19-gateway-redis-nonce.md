# Implementation Plan: Redis NonceStore for @bolyra/gateway v0.2.0

**Date:** 2026-06-19
**Spec:** `docs/superpowers/specs/2026-06-19-gateway-redis-nonce-design.md`
**PDLC:** `pdlc-2026-06-19-gateway-redis-nonce`

## Task Breakdown

### Task 1: Add `redis` dependency and bump version (S, parallel)

**Description:** Add `redis` ^4.7.0 as a runtime dependency to `integrations/gateway/package.json`. Bump version from 0.1.0 to 0.2.0.

**Input files:**
- `integrations/gateway/package.json`

**Output files:**
- `integrations/gateway/package.json`

**Test:** `npm ls redis` shows redis installed.

---

### Task 2: Update NonceConfig types (S, parallel)

**Description:** Update `NonceConfig` in `integrations/gateway/src/types.ts` to accept `store: 'memory' | 'redis'` and add optional `redis` sub-config with `url`, `keyPrefix`, and `connectTimeout` fields.

**Input files:**
- `integrations/gateway/src/types.ts`

**Output files:**
- `integrations/gateway/src/types.ts`

**Test:** `npx tsc --noEmit` passes.

---

### Task 3: Create RedisNonceStore class (M, parallel)

**Description:** Create `integrations/gateway/src/redis-nonce-store.ts` implementing the `NonceStore` interface from `@bolyra/mcp`. Uses `SET NX EX` for atomic mark-if-fresh. Includes key prefix, lazy connection, reconnect strategy, `close()` method. Fail-closed on Redis unavailability.

**Input files:**
- `integrations/mcp/src/types.ts` (NonceStore interface)
- `integrations/mcp/src/nonce-store.ts` (MemoryNonceStore reference)

**Output files:**
- `integrations/gateway/src/redis-nonce-store.ts`

**Test:** `npx tsc --noEmit` passes.

---

### Task 4: Update config validation (S, sequential -- depends on Task 2)

**Description:** Update `validateConfig()` in `integrations/gateway/src/config.ts` to:
- Accept `store: 'redis'` (not just `'memory'`)
- Require `nonce.redis.url` when `store === 'redis'`
- Reject `nonce.redis.url` containing unresolved `${...}`
- Reject unknown `store` values
- Update the `loadConfig` nonce merge to handle the redis sub-config

**Input files:**
- `integrations/gateway/src/config.ts`
- `integrations/gateway/src/types.ts`

**Output files:**
- `integrations/gateway/src/config.ts`

**Test:** Existing + new config tests pass.

---

### Task 5: Update CLI nonce store factory and banner (S, sequential -- depends on Tasks 2, 3)

**Description:** Update `integrations/gateway/src/cli.ts` to:
- Import `RedisNonceStore`
- Select nonce store based on `config.nonce.store`
- Add graceful shutdown of `RedisNonceStore.close()` on SIGINT/SIGTERM
- Add nonce store info line to startup banner

**Input files:**
- `integrations/gateway/src/cli.ts`
- `integrations/gateway/src/redis-nonce-store.ts`

**Output files:**
- `integrations/gateway/src/cli.ts`

**Test:** `npx tsc --noEmit` passes.

---

### Task 6: Update exports (S, sequential -- depends on Task 3)

**Description:** Export `RedisNonceStore` and `RedisNonceStoreOptions` from `integrations/gateway/src/index.ts`.

**Input files:**
- `integrations/gateway/src/index.ts`

**Output files:**
- `integrations/gateway/src/index.ts`

**Test:** `npx tsc --noEmit` passes.

---

### Task 7: Write unit tests (M, sequential -- depends on Tasks 2, 3, 4)

**Description:** Create `integrations/gateway/test/redis-nonce-store.test.ts` with:
- RedisNonceStore mock tests (markIfFresh SET NX EX, returns true/false, prefix, close)
- Add Redis config validation tests to existing `test/config.test.ts`

**Input files:**
- `integrations/gateway/src/redis-nonce-store.ts`
- `integrations/gateway/src/config.ts`
- `integrations/gateway/test/config.test.ts`

**Output files:**
- `integrations/gateway/test/redis-nonce-store.test.ts`
- `integrations/gateway/test/config.test.ts`

**Test command:** `cd integrations/gateway && npx jest`

---

### Task 8: Update README (S, sequential -- depends on Tasks 1-6)

**Description:** Update `integrations/gateway/README.md` with Redis nonce store configuration documentation, library usage example, and updated exports table.

**Input files:**
- `integrations/gateway/README.md`

**Output files:**
- `integrations/gateway/README.md`

**Test:** N/A (documentation).

---

## Dependency Graph

```
Task 1 (package.json)  ──┐
Task 2 (types)  ─────────┤──> Task 4 (config validation)
Task 3 (RedisNonceStore) ┤──> Task 5 (CLI wiring)
                          ├──> Task 6 (exports)
                          └──> Task 7 (tests) ──> Task 8 (README)
```

Tasks 1, 2, 3 are parallel. Tasks 4-8 are sequential.

## Estimated Scope

- **Total tasks:** 8
- **Parallelizable:** 3 (Tasks 1, 2, 3)
- **Sequential:** 5 (Tasks 4, 5, 6, 7, 8)
- **Size:** 4S + 2M + 2S = mostly small, two medium
