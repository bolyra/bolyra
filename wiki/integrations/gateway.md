---
title: Gateway
visibility: public
sources:
  - integrations/gateway/README.md
  - integrations/gateway/package.json
  - integrations/gateway/src/
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [gateway, reverse-proxy, mcp, zkp, receipts, redis, docker]
---

Standalone reverse proxy that verifies agent ZKP credentials before forwarding requests to upstream MCP servers. Handles proof verification, replay protection, scope enforcement, and signed audit receipts.

## Overview

`@bolyra/gateway` (v0.2.1) sits in front of any MCP server. Agents send proof bundles; the gateway verifies them and proxies authorized requests with `X-Bolyra-*` headers. The upstream server never needs to import Bolyra.

- **npm:** `@bolyra/gateway`
- **CLI:** `npx @bolyra/gateway`
- **Docker:** `ghcr.io/bolyra/gateway`
- **Deps:** `@bolyra/mcp`, `@bolyra/receipts`, `@bolyra/sdk`, `@noble/hashes`, `redis`, `yaml`
- **License:** Apache-2.0

## Key Concepts

- **Request routing:** `GET /healthz` is intercepted. Non-`tools/call` JSON-RPC methods pass through without auth. `tools/call` methods require proof verification.
- **X-Bolyra-* headers:** Injected into proxied requests after verification: `X-Bolyra-Verified`, `X-Bolyra-DID`, `X-Bolyra-Score`, `X-Bolyra-Permissions`, `X-Bolyra-Chain-Depth`, `X-Bolyra-Receipt-ID`, `X-Bolyra-HMAC`.
- **Nonce replay protection:** In-memory (default) or Redis-backed for multi-instance deployments. Fail-closed: if Redis is unreachable, gateway returns HTTP 500.
- **Receipt output:** Three modes -- `file` (day-rotated JSON), `stdout` (NDJSON), `webhook` (HTTP POST). Non-blocking; write failures never interrupt requests.
- **HMAC signing:** Optional HMAC-SHA256 on `X-Bolyra-*` headers so upstream can verify the gateway set them.

## How It Works

```
Agent (with proof) -> Gateway -> Upstream MCP Server
                      1. Parse Authorization header
                      2. verifyBundle() from @bolyra/mcp
                      3. checkToolPolicy()
                      4. Nonce replay check
                      5. Emit signed receipt
                      6. Proxy request + X-Bolyra-* headers
```

### Configuration

Config via YAML file (`gateway.yaml`) and/or CLI flags (flags override file). Env var substitution supported via `${VAR_NAME}` syntax.

Key config sections: `target`, `port`, `devMode`, `credentials`, `tools` (per-tool bitmask policies), `nonce` (store type + Redis config), `receipts` (output mode + signing), `health`, `hmac`.

### Library API

For embedding in a custom server:

```ts
import { createGatewayProxy, createGatewayMiddleware, loadConfig } from '@bolyra/gateway';

// Full proxy server
const server = createGatewayProxy({ config: loadConfig({ target: 'http://localhost:3000/mcp', dev: true }) });

// Or just the middleware
const middleware = createGatewayMiddleware({ config });
```

### Source layout

| File | Purpose |
|------|---------|
| `src/cli.ts` | CLI entry point |
| `src/config.ts` | YAML config loading + validation |
| `src/proxy.ts` | `createGatewayProxy` |
| `src/middleware.ts` | `createGatewayMiddleware` |
| `src/headers.ts` | `injectBolyraHeaders`, HMAC compute/verify |
| `src/receipts.ts` | `createReceiptWriter` (file/stdout/webhook) |
| `src/redis-nonce-store.ts` | `RedisNonceStore` |
| `src/health.ts` | `/healthz` handler |

### Docker

Available as `ghcr.io/bolyra/gateway` (linux/amd64, linux/arm64). Runs as non-root user `bolyra` (UID 1001) on `node:22-alpine`. Config mount at `/etc/bolyra/gateway.yaml`, receipts at `/app/receipts/`.

## Current Status

v0.2.1 on npm. Docker image on GHCR. Redis nonce store shipped in v0.2.0. 64 tests. Security audit completed (2C+4H+3M fixed).

## See Also

- [MCP](mcp.md) -- the auth verification library this gateway builds on
- [Payment Protocols](payment-protocols.md) -- commerce protocol adapters that sit alongside the gateway
