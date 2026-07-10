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
  --dev                Enable Bolyra Core mode (classical checks: tool policy,
                       nonce replay, signed receipts, credential binding
                       against registered credentials; ZK proof verification
                       off. Without registered credentials, permission claims
                       are self-asserted — see Credential Binding below)
  --credentials <path> Credentials file (YAML/JSON map: commitment ->
                       { permissionBitmask, expiryTimestamp? }); overrides
                       the config's credentials section
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

# Bolyra Core mode: classical checks only, ZK proof verification skipped
devMode: false

# Registered credentials (see "Credential Binding" below).
# Core mode (devMode: true): claims are checked against this registry —
#   unknown commitments, forged masks, and expired credentials are denied.
# Production mode: this map becomes the resolveCredential source for
#   verifyBundle's Poseidon3 scopeCommitment binding (expiryTimestamp
#   required per entry).
# type: registry (on-chain resolution) is not supported by the packaged
# gateway yet and fails validation — use the library resolveCredential
# option for custom resolution.
credentials:
  type: static
  map:
    "48201394857102938471029384":     # credential commitment (decimal)
      permissionBitmask: 3            # READ_DATA | WRITE_DATA
      expiryTimestamp: "1893456000"   # unix seconds; optional in Core mode

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

# Receipt signing — every allow/deny decision is ES256K-signed (see
# "Signed Receipts" below). Without privateKey an ephemeral key is
# generated at startup; set it for a stable, pinnable signer address.
receipts:
  enabled: true
  issuer: "my-gateway"
  keyId: "k1"
  privateKey: "${BOLYRA_RECEIPT_KEY}"  # 32-byte hex secp256k1 key, env var substitution
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
| `createGatewayReceiptSigner(config, override?)` | Resolve the ES256K receipt signer (configured key or ephemeral) |
| `createHealthHandler(config)` | Create /healthz endpoint handler |
| `extractToolName(body)` | Extract tool name from JSON-RPC body |
| `loadCredentialsFile(path)` | Load a `--credentials` file (bare map or full section) |
| `buildCredentialRegistry(credentials)` | Compile a static credentials section into a lookup registry |
| `checkCredentialBinding(bundle, authCtx, registry)` | Core-mode registered-credential check (see Credential Binding) |
| `createStaticCredentialResolver(credentials)` | Static `resolveCredential` for production scopeCommitment binding |
| `hasStaticCredentials(credentials)` | True when a usable static credential map is configured |
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
| `X-Bolyra-Receipt-ID` | Signed receipt id for this decision (when receipts enabled) |
| `X-Bolyra-HMAC` | HMAC-SHA256 signature (when HMAC configured) |

The upstream server can use these headers for logging/auditing without importing Bolyra.

## Signed Receipts (v0.3.0+)

Every `tools/call` decision — **allow and deny, dev mode and production** —
produces an ES256K-signed receipt (`SignedReceipt` from
[`@bolyra/receipts`](../receipts/README.md): secp256k1 + keccak256,
Ethereum-compatible recovery). This includes rejections with no usable proof
bundle at all: a missing or malformed `Authorization` header still leaves a
signed **anonymous deny receipt**, so the audit trail has no unsigned gaps.

Each receipt carries the verdict (`decision.allowed`), a human-readable
`reasonCode` (which tool, which permissions were required vs. held), the agent
DID when known, score, permission bitmask, delegation chain depth, hashes of
the presented proof material, and the decision timestamp. Any edit to a
receipt breaks its signature.

**Signing key resolution:**

1. `receiptSigner` option (library embedders)
2. `receipts.privateKey` from the config (recommended for production)
3. Otherwise an **ephemeral key** is generated at startup. Receipts remain
   independently verifiable — the signer address is recoverable from every
   signature — but the address rotates on restart. The CLI prints the signer
   address in the startup banner and, in `file` output mode, persists it to
   `{receipt-dir}/signer.json` so auditors can pin the trust anchor.

**Independent verification** needs only the receipt (plus, optionally, the
pinned signer address) — no gateway, no database:

```typescript
import { verifyReceipt } from '@bolyra/receipts';

const receipt = JSON.parse(fs.readFileSync('receipts/2026-07-10/....json', 'utf8'));
verifyReceipt(receipt);                  // true — signature + payload hash check
verifyReceipt(receipt, pinnedSigner);    // true — also pins the signer address
```

### Receipt Output Modes

| Mode | Description |
|------|-------------|
| `file` | JSON files in day-rotated directories: `receipts/2026-06-18/{timestamp}-{receipt-id}.json`, plus `signer.json` with the pinned signer address |
| `stdout` | NDJSON to stdout (one JSON line per receipt) |
| `webhook` | HTTP POST to configured URL with optional auth headers |

All modes are non-blocking. Write and signing failures are logged but never
interrupt request processing. The signing key is probe-validated at startup;
in the exceptional case that signing still fails at runtime, the decision is
recorded as a raw JSON record explicitly tagged `"unsigned": true` (with the
signing error), so audit consumers can detect the gap — an unsigned record
can never masquerade as a signed receipt.

Receipts always record the gateway's **final** decision: a request that
authenticates successfully but fails tool policy gets a *deny* receipt. A
bundle that parses as JSON but is missing proof material entirely is denied
fail-closed (HTTP 401) with a signed anonymous receipt.

## Credential Binding (v0.4.0+)

In **Core mode** (`--dev`) proofs are mocked, so the permission mask inside a
bundle is asserted by the caller. Registering credentials turns that claim
into an enforced check — the same registered-credential pattern as
[`examples/verified-actions-demo`](../../examples/verified-actions-demo/README.md),
now packaged:

- **unknown commitment** → 401 + signed deny receipt (`credential_unknown`)
- **claimed mask ≠ registered grant** (forged bundle) → 401 + signed deny
  receipt (`credential_mismatch`)
- **delegation chain expanding beyond the grant** → 401 (`credential_mismatch`
  — scope narrowing is one-way)
- **registered expiry passed** → 401 + signed deny receipt
  (`credential_expired`)

All denials are fail-closed and receipted like every other decision.

**Registering a dev credential.** A commitment in Core mode is an opaque
identifier the platform assigns (production commitments are Poseidon hashes
of the credential). Generate one and register it:

```bash
# 1. Generate a commitment
node -e "console.log(BigInt('0x' + require('crypto').randomBytes(16).toString('hex')).toString())"

# 2. Register it (credentials.yaml)
cat > credentials.yaml << 'EOF'
"48201394857102938471029384":
  permissionBitmask: 3        # READ_DATA | WRITE_DATA
EOF

# 3. Run with binding enforced
npx @bolyra/gateway --target http://localhost:3000/mcp --dev --credentials ./credentials.yaml
```

Hand the commitment (and its granted mask) to the agent; its proof bundles
must carry exactly that identity and mask. The `--credentials` file can be a
bare map (above) or the full config-section shape (`type: static`, `map:`);
the `credentials:` section in `gateway.yaml` is equivalent.

**Without registered credentials**, Core mode stays frictionless for
tutorials: any claim passes (current behavior), but the gateway warns at
startup and every allow receipt is flagged
`[credential-binding: none — permission claims self-asserted]` so audit
consumers can see the tradeoff — the same visibility pattern as the
ephemeral receipt-signing key.

**In production mode** the same `credentials` section is compiled into a
`resolveCredential` implementation, engaging `verifyBundle`'s cryptographic
binding: the verifier recomputes `Poseidon3(permissionBitmask, commitment,
expiryTimestamp)` from the registered credential and requires it to equal
the proof's public `scopeCommitment` output — a forged mask cannot produce
a valid proof. `expiryTimestamp` is therefore required per entry in
production. Library embedders can still pass `resolveCredential` directly;
it takes precedence over the config section.

## Security Model

The gateway is the **trust boundary**. Agents present proof bundles; the gateway verifies them before forwarding.

**Deployment guidance:**
- Bind your upstream MCP server to localhost or a private network
- Only expose the gateway to the internet
- Use HTTPS between clients and the gateway
- Configure HMAC signing if you need to verify X-Bolyra-* headers were set by the gateway

**Threats addressed:**
- Replay attacks (nonce store)
- Credential substitution (production: Poseidon3 scope commitment binding)
- Forged permission claims in Core mode (registered-credential binding, when credentials are configured)
- Delegation escalation (one-way scope narrowing, circuit-enforced)
- Scope bypass (per-tool bitmask enforcement)
- Header injection (optional HMAC signing)
- Audit evasion (ES256K-signed receipts for every decision — allow and deny, including anonymous rejections; tamper-evident via `verifyReceipt`)

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
# Bolyra Core mode -- classical checks, no circuits, no config file needed
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
