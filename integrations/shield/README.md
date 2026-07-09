# @bolyra/shield

Stdio MCP auth proxy. Wrap any MCP server with per-tool permission enforcement, replay protection, and audit receipts. No code changes to the server.

## Quick Start

```bash
npx @bolyra/shield --server "npx @modelcontextprotocol/server-filesystem /tmp" --dev
```

Shield spawns the target server as a child process, intercepts `tools/call` requests, verifies agent credentials, and enforces tool policies before forwarding.

## Config

Create `shield.yaml`:

```yaml
devMode: true
defaultDeny: true

nonce:
  store: memory
  maxProofAge: 300

receipts:
  enabled: true
  output: stderr

tools:
  read_file:
    requireBitmask: 1    # READ_DATA
  write_file:
    requireBitmask: 2    # WRITE_DATA
  delete_file:
    requireBitmask: 2    # WRITE_DATA
```

Then:

```bash
npx @bolyra/shield --server "node my-server.js" --config shield.yaml
```

## Default Deny

By default, tools without a policy entry are allowed through (only authentication is checked). Set `defaultDeny: true` to reject any `tools/call` for tool names not listed in the `tools:` map.

## Learn Mode

Don't write the config by hand — generate a safe starting point from the server's own tool list:

```bash
npx @bolyra/shield --learn --server "node my-server.js"
```

Learn mode spawns the server, performs the MCP handshake (`initialize` → `notifications/initialized` → `tools/list`, following pagination), then writes `shield.yaml` (or the `--config` path) with:

- `defaultDeny: true` — anything the server adds later is rejected until you allow it
- every discovered tool at `requireBitmask: 1` (READ_DATA) — the least-privilege floor
- a `_generated` provenance block (source command + timestamp)

It never overwrites an existing config file, caps pagination at 50 pages, and times out after 30 seconds. The output is a starting point: review each tool and raise its `requireBitmask` (e.g. `write_file` → `2`) before production use.

## How It Works

```
Agent ←stdin/stdout→ Shield ←stdin/stdout→ MCP Server
                       │
                 verifyBundle()
                 checkToolPolicy()
                 nonceStore.markIfFresh()
                 emitReceipt()
```

- `initialize`, `tools/list`, `ping` — forwarded without auth
- `tools/call` — proof extracted from `params._meta.bolyra`, verified, policy checked, then forwarded or rejected
- Receipts emitted to stderr (stdout is the MCP transport)

## Permission Bitmask

| Bit | Permission |
|-----|-----------|
| 0 | READ_DATA |
| 1 | WRITE_DATA |
| 2 | FINANCIAL_SMALL |
| 3 | FINANCIAL_MEDIUM |
| 4 | FINANCIAL_UNLIMITED |
| 5 | SIGN_ON_BEHALF |
| 6 | SUB_DELEGATE |
| 7 | ACCESS_PII |

## Shield vs Gateway

| | Shield | Gateway |
|---|--------|---------|
| Transport | stdio | HTTP |
| Use case | Local MCP servers (Claude Desktop, Cursor) | Remote/networked MCP servers |
| How it wraps | Spawns child process | Reverse proxy |
| Proof source | `params._meta.bolyra` | `Authorization: Bolyra <base64>` header |
| Receipts | stderr | stdout/file/webhook |

Both use the same `verifyBundle()` and `checkToolPolicy()` from `@bolyra/mcp`.

## Library Usage

```typescript
import { createShield, loadShieldConfig } from '@bolyra/shield';

const config = loadShieldConfig('./shield.yaml');
const { child, stop } = createShield(config);
```

## Links

- [Gateway (HTTP)](../gateway/README.md) — for HTTP MCP servers
- [MCP Middleware](../mcp/README.md) — for embedding auth in your server code
- [Bolyra docs](https://bolyra.ai)
