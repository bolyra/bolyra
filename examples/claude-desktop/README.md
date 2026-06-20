# Claude Desktop + Bolyra Integration

This example demonstrates two ways to add Bolyra ZKP authentication to Claude Desktop's MCP tool calls.

## Architecture

### Path A: Stdio Proxy (Recommended for first try)

```
Claude Desktop
  |  spawns via claude_desktop_config.json
  v
bolyra-proxy (stdio)
  |  generates ZKP proof, injects into _meta.bolyra
  v
MCP server (Bolyra-gated tools)
```

The proxy sits between Claude Desktop and a Bolyra-protected MCP server. It intercepts every `tools/call` request, generates a fresh ZKP handshake proof, and injects it into the request before forwarding.

### Path B: HTTP Gateway

```
Claude Desktop / HTTP client
  |  HTTP POST with Authorization: Bolyra <proof>
  v
@bolyra/gateway (port 4100, reverse proxy)
  |  verifies proof, injects X-Bolyra-* headers
  v
upstream MCP server (port 3001)
```

The gateway acts as a standard HTTP reverse proxy. It verifies the Bolyra proof bundle from the `Authorization` header before forwarding requests to the upstream MCP server.

## Prerequisites

- Node.js 18+
- This repository cloned locally
- Claude Desktop installed (for manual testing only -- E2E tests run without it)

## Quick Test (No Claude Desktop Required)

```bash
# One-time setup
bash scripts/setup.sh

# Run all E2E tests
npm test
```

The E2E tests spawn real processes, send real JSON-RPC messages, and verify real responses.

## Try with Claude Desktop

### Path A: Stdio Proxy

1. Run setup:
   ```bash
   bash scripts/setup.sh
   ```

2. Copy the generated config into Claude Desktop:
   - Open Claude Desktop Settings > Developer > Edit Config
   - Merge the contents of `configs/proxy-config-resolved.json` into your `claude_desktop_config.json`

3. Restart Claude Desktop

4. Try using any tool -- you'll see Bolyra auth logs in Claude Desktop's MCP server logs:
   ```
   [bolyra-proxy] proof for read_file in 203ms (v=1, depth=0)
   ```

### Path B: HTTP Gateway

1. Start the upstream MCP server:
   ```bash
   node dist/src/server.js
   ```

2. In another terminal, start the gateway:
   ```bash
   npx @bolyra/gateway --target http://localhost:3001 --dev --port 4100
   ```

3. The gateway now requires `Authorization: Bolyra <proof>` on all non-initialization requests. This path is primarily for programmatic clients that can generate proof bundles.

## Config Snippets

### Stdio Proxy (`configs/proxy-config.json`)

```json
{
  "mcpServers": {
    "bolyra-protected-fs": {
      "command": "node",
      "args": ["<REPO_ROOT>/examples/mcp-demo/dist/bolyra-proxy.js"],
      "env": {
        "BOLYRA_RAPIDSNARK": "<REPO_ROOT>/circuits/build/rapidsnark_prover"
      }
    }
  }
}
```

Replace `<REPO_ROOT>` with your absolute path to the bolyra repo, or run `bash scripts/setup.sh` to auto-generate a resolved version.

### HTTP Gateway (`configs/gateway-config.json`)

```json
{
  "mcpServers": {
    "bolyra-gateway": {
      "url": "http://localhost:4100/mcp",
      "transport": "streamable-http"
    }
  }
}
```

## Troubleshooting

**"rapidsnark binary not found"**
The proxy falls back to snarkjs (JavaScript) for proof generation, which is ~100x slower. To use rapidsnark, build it from source or download a prebuilt binary and place it at `circuits/build/rapidsnark_prover`.

**Port conflicts**
The upstream server defaults to port 3001 and the gateway to port 4100. Override with environment variables:
```bash
PORT=3002 node dist/src/server.js
npx @bolyra/gateway --target http://localhost:3002 --port 4200
```

**"Cannot find module '@bolyra/sdk'"**
Run `bash scripts/setup.sh` to install dependencies with the correct file: references to the monorepo packages.

**Claude Desktop does not show the MCP server**
Verify the path in `claude_desktop_config.json` is absolute and correct. Check Claude Desktop's developer console for errors.

**Proof generation fails**
Ensure circuit build artifacts exist: `ls circuits/build/*.zkey`. If missing, run `npm run compile:circuits` from the repo root (requires Circom 2 installed).
