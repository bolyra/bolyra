# @bolyra/gateway

Bolyra MCP Auth Gateway -- standalone reverse proxy that verifies agent ZKP credentials before forwarding requests to upstream MCP servers.

Put `@bolyra/gateway` in front of your MCP server; it verifies agent authority, prevents replay, enforces delegated scopes, and gives you signed audit logs for every tool call.

## Quickstart

```bash
# Install
npm install @bolyra/gateway

# Create a config file (optional)
cat > gateway.yaml << 'EOF'
target: http://localhost:3000/mcp
port: 4100
devMode: true
EOF

# Run
npx @bolyra/gateway --config ./gateway.yaml
```

Or run directly with CLI flags:

```bash
npx @bolyra/gateway --target http://localhost:3000/mcp --dev --port 4100
```

## How It Works

```
                  +----------------------------------+
                  |         @bolyra/gateway           |
   Agent -------->|                                    |--------> Upstream MCP Server
  (with proof     |  1. Parse Authorization header     |          (unmodified)
   bundle)        |  2. verifyBundle() from @bolyra/mcp|
                  |  3. checkToolPolicy()              |
                  |  4. Nonce replay check              |
                  |  5. Emit signed receipt             |
                  |  6. Proxy request + X-Bolyra-* hdrs|
                  |                                    |
                  |  Config: gateway.yaml              |
                  |  Receipts: ./receipts/ or stdout    |
                  +----------------------------------+
```

**Request routing:**

1. `GET /healthz` -- returns gateway status (intercepted, not proxied)
2. JSON-RPC method != `tools/call` -- forwarded to upstream without auth
3. JSON-RPC method == `tools/call` -- auth verified, then forwarded if authorized

## CLI Reference

```
npx @bolyra/gateway [options]

Options:
  --target <url>       Upstream MCP server URL (required unless in config)
  --port <number>      Gateway listen port (default: 4100)
  --config <path>      Path to gateway config file (default: ./gateway.yaml)
  --dev                Enable dev mode (mock verification, no real ZKP)
  --receipt-dir <path> Directory for receipt JSON files (default: ./receipts/)
  --receipt-stdout     Write receipts to stdout (NDJSON)
  --no-receipts        Disable receipt generation
  --network <name>     Bolyra network (default: base-sepolia)
  --help               Show help
  --version            Show version
```

CLI flags override config file values.

## Config File Reference

```yaml
# gateway.yaml
target: http://localhost:3000/mcp
port: 4100
network: base-sepolia

# Dev mode skips real ZKP verification
devMode: false

# Credential resolution
credentials:
  type: registry
  registryAddress: "0x..."
  rpcUrl: "https://base-sepolia.g.alchemy.com/v2/..."

# Per-tool policies
tools:
  write_file:
    requireBitmask: 2      # WRITE_DATA (0b10)
  delete_file:
    requireBitmask: 6      # WRITE_DATA + FINANCIAL_SMALL (0b110)
    maxChainDepth: 0        # Direct credentials only
  transfer_funds:
    requireBitmask: 28     # FINANCIAL_* (0b11100)
    minScore: 90

# Nonce replay protection
nonce:
  store: memory             # "memory" (default) or "redis"
  maxProofAge: 300          # seconds
  # Redis config (required when store: redis)
  # redis:
  #   url: ${REDIS_URL}           # required
  #   keyPrefix: "bolyra:nonce:"  # optional, default shown
  #   connectTimeout: 5000        # optional, ms

# Receipt signing
receipts:
  enabled: true
  issuer: "my-gateway"
  keyId: "k1"
  privateKey: "${BOLYRA_RECEIPT_KEY}"  # env var substitution
  output: file              # "file", "stdout", or "webhook"
  dir: ./receipts/

# Health check
health:
  enabled: true
  path: /healthz

# Optional HMAC signing for X-Bolyra-* headers
# hmac:
#   secret: "hex-encoded-shared-secret"
```

Environment variables are substituted in string values using `${VAR_NAME}` syntax.

## Library API

For embedding the gateway middleware in your own server:

```typescript
import {
  createGatewayMiddleware,
  createGatewayProxy,
  loadConfig,
  injectBolyraHeaders,
  computeHmac,
  verifyHmac,
  createReceiptWriter,
  createHealthHandler,
} from '@bolyra/gateway';
import type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  GatewayRequest,
} from '@bolyra/gateway';

// Option 1: Full proxy server
const config = loadConfig({ target: 'http://localhost:3000/mcp', dev: true });
const server = createGatewayProxy({ config });
server.listen(4100);

// Option 2: Just the middleware (for custom servers)
const middleware = createGatewayMiddleware({ config });
// Use in your request handler:
// const authorized = await middleware(req, res, toolName);
```

### Exports

| Export | Description |
|--------|-------------|
| `createGatewayProxy(options)` | Create full reverse proxy HTTP server |
| `createGatewayMiddleware(options)` | Auth verification middleware only |
| `loadConfig(flags?)` | Load and validate gateway configuration |
| `injectBolyraHeaders(authCtx, receiptId?)` | Build X-Bolyra-* headers |
| `computeHmac(headers, secret)` | HMAC-SHA256 sign X-Bolyra-* headers |
| `verifyHmac(headers, secret, hmac)` | Verify HMAC on X-Bolyra-* headers |
| `createReceiptWriter(config)` | Create pluggable receipt output |
| `createHealthHandler(config)` | Create /healthz endpoint handler |
| `extractToolName(body)` | Extract tool name from JSON-RPC body |
| `RedisNonceStore` | Redis-backed NonceStore for multi-instance deployments |

## Redis Nonce Store (v0.2.0+)

For multi-instance deployments, use Redis for shared nonce replay protection:

```yaml
# gateway.yaml
nonce:
  store: redis
  maxProofAge: 300
  redis:
    url: ${REDIS_URL}
    keyPrefix: "bolyra:nonce:"   # optional
```

Library usage:

```typescript
import { createGatewayMiddleware, RedisNonceStore } from '@bolyra/gateway';

const store = new RedisNonceStore({ url: 'redis://localhost:6379' });
const middleware = createGatewayMiddleware({ config, nonceStore: store });

// Graceful shutdown
process.on('SIGTERM', () => store.close());
```

**Fail-closed behavior:** If Redis is unreachable, the gateway returns HTTP 500, never passes requests through. Monitor Redis availability as a critical dependency.

## X-Bolyra-* Headers

When a request passes verification, the gateway injects these headers into the proxied request:

| Header | Value |
|--------|-------|
| `X-Bolyra-Verified` | `true` |
| `X-Bolyra-DID` | `did:bolyra:{network}:{commitment}` |
| `X-Bolyra-Score` | Verification score (0-100) |
| `X-Bolyra-Permissions` | Effective permission bitmask (decimal) |
| `X-Bolyra-Chain-Depth` | Delegation chain depth (0 = direct) |
| `X-Bolyra-Receipt-ID` | Receipt ID (when receipts enabled) |
| `X-Bolyra-HMAC` | HMAC-SHA256 signature (when HMAC configured) |

The upstream server can use these headers for logging/auditing without importing Bolyra.

## Receipt Output Modes

| Mode | Description |
|------|-------------|
| `file` | JSON files in day-rotated directories: `receipts/2026-06-18/{timestamp}-{id}.json` |
| `stdout` | NDJSON to stdout (one JSON line per receipt) |
| `webhook` | HTTP POST to configured URL with optional auth headers |

All modes are non-blocking. Write failures are logged but never interrupt request processing.

## Security Model

The gateway is the **trust boundary**. Agents present proof bundles; the gateway verifies them before forwarding.

**Deployment guidance:**
- Bind your upstream MCP server to localhost or a private network
- Only expose the gateway to the internet
- Use HTTPS between clients and the gateway
- Configure HMAC signing if you need to verify X-Bolyra-* headers were set by the gateway

**Threats addressed:**
- Replay attacks (nonce store)
- Credential substitution (Poseidon3 scope commitment binding)
- Delegation escalation (one-way scope narrowing, circuit-enforced)
- Scope bypass (per-tool bitmask enforcement)
- Header injection (optional HMAC signing)
- Audit evasion (receipts for both allows and denials)

## Permission Bitmask Reference

| Bit | Permission | Value |
|-----|-----------|-------|
| 0 | READ_DATA | 1 |
| 1 | WRITE_DATA | 2 |
| 2 | FINANCIAL_SMALL (<$100) | 4 |
| 3 | FINANCIAL_MEDIUM (<$10K) | 8 |
| 4 | FINANCIAL_UNLIMITED | 16 |
| 5 | SIGN_ON_BEHALF | 32 |
| 6 | SUB_DELEGATE | 64 |
| 7 | ACCESS_PII | 128 |

Higher tiers imply lower (e.g., FINANCIAL_MEDIUM implies FINANCIAL_SMALL).

## Docker

Run the gateway as a container with zero Node.js setup required.

### Pull from GHCR

```bash
docker pull ghcr.io/bolyra/gateway:latest
```

### Quick Start

```bash
# Dev mode -- mock verification, no config file needed
docker run --rm -p 4100:4100 ghcr.io/bolyra/gateway \
  --target http://host.docker.internal:3000/mcp --dev
```

### Production

```bash
# Mount config file + set env vars
docker run -d \
  -v $(pwd)/gateway.yaml:/etc/bolyra/gateway.yaml:ro \
  -e REDIS_URL=redis://redis:6379 \
  -e BOLYRA_RECEIPT_KEY=hex-encoded-key \
  -p 4100:4100 \
  ghcr.io/bolyra/gateway
```

### Build Locally

```bash
# From repo root
docker build -f Dockerfile.gateway -t bolyra-gateway:local .

# Run with local build
docker run --rm -p 4100:4100 bolyra-gateway:local \
  --target http://host.docker.internal:3000/mcp --dev

# Verify health
curl http://localhost:4100/healthz
```

### Override Port

```bash
docker run --rm -p 8080:8080 ghcr.io/bolyra/gateway \
  --target http://upstream:3000/mcp --port 8080 --dev
```

### Image Details

- **Base:** `node:22-alpine`
- **User:** `bolyra` (UID 1001, non-root)
- **Port:** 4100 (default)
- **Healthcheck:** `GET /healthz` every 30s
- **Config mount:** `/etc/bolyra/gateway.yaml`
- **Receipt dir:** `/app/receipts/` (writable)
- **Architectures:** `linux/amd64`, `linux/arm64`

CLI flags passed after the image name override config file values. See [CLI Reference](#cli-reference) above.

## License

Apache-2.0
