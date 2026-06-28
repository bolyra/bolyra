# Claude Desktop Integration -- Design Spec

**PDLC:** `pdlc-2026-06-20-claude-desktop-integration`
**Date:** 2026-06-20
**Status:** Draft

## Problem

Bolyra's most likely first touchpoint for new users is Claude Desktop. A developer who discovers Bolyra will want to try it with the MCP host they already use daily. Today, the existing `examples/mcp-demo/` has a working stdio proxy (`bolyra-proxy.ts`) and a protected server (`server-fixed.ts`), but:

1. There is no step-by-step guide from "I have Claude Desktop" to "I see Bolyra auth working."
2. The `claude_desktop_config.json` snippet is not documented anywhere users would find it.
3. There is no automated test that verifies the integration end-to-end without manual Claude Desktop interaction.
4. The HTTP gateway path (`@bolyra/gateway`) is not demonstrated with Claude Desktop at all.

This gap means every new user has to reverse-engineer the setup from scattered source files.

## Goals

1. A self-contained `examples/claude-desktop/` directory that a user can clone and run.
2. Two documented integration paths:
   - **Path A (Stdio Proxy):** Claude Desktop -> `bolyra-proxy` (stdio) -> `server-fixed` (protected MCP server)
   - **Path B (HTTP Gateway):** Claude Desktop -> standard MCP server (HTTP/SSE) -> `@bolyra/gateway` (reverse proxy) -> upstream MCP server
3. Copy-paste `claude_desktop_config.json` snippets for both paths.
4. An automated E2E test script that exercises both paths programmatically (no manual Claude Desktop interaction required).
5. README with step-by-step setup guide.

## Non-Goals

- Modifying the existing `bolyra-proxy.ts` or `server-fixed.ts` (reuse as-is).
- Supporting non-Claude MCP hosts (Cursor, Windsurf, etc.) in this iteration.
- Real ZKP verification in tests (use `--dev` mode for gateway; the stdio proxy already uses demo identities with mock-speed proofs via rapidsnark).

## Architecture

### Path A: Stdio Proxy

```
Claude Desktop
  |
  | spawns via claude_desktop_config.json
  v
bolyra-proxy (stdio, Node.js)
  |
  | spawns as child process
  v
server-fixed (stdio, protected MCP server)
  |
  | tools/call with _meta.bolyra proof bundle
  v
withBolyraAuthStdio verifies -> responds
```

This path already works. The deliverable is documentation and a test that exercises it programmatically by simulating the stdio JSON-RPC exchange that Claude Desktop would perform.

### Path B: HTTP Gateway

```
Claude Desktop
  |
  | HTTP POST to gateway endpoint (configured as streamable-http MCP server)
  v
@bolyra/gateway (HTTP reverse proxy, port 4100)
  |
  | verifies Authorization header (Bolyra proof bundle)
  | injects X-Bolyra-* headers
  v
upstream MCP server (HTTP, port 3001)
  |
  | standard MCP tool handling
  v
responds
```

For Claude Desktop, the gateway appears as a standard HTTP MCP server. The client must attach the proof bundle in the `Authorization` header. This requires a thin client-side shim or a proxy similar to Path A but for HTTP transport.

**Design decision:** For the E2E test, we do NOT require Claude Desktop to be running. Instead:
- The test starts the upstream MCP server (HTTP) and the gateway programmatically.
- The test acts as an MCP client, sending JSON-RPC requests to the gateway with the correct Authorization header.
- The test verifies: (a) requests without auth are rejected, (b) requests with valid auth are proxied and return correct results, (c) receipts are generated.

### Test Architecture

```
test-e2e.ts
  |
  |-- Path A test:
  |     Spawn bolyra-proxy as child process (stdio)
  |     Send JSON-RPC initialize + tools/list + tools/call via stdin
  |     Read responses from stdout
  |     Verify: tool call succeeds, _meta.bolyra was injected
  |
  |-- Path B test:
  |     Start upstream MCP server on localhost:3001
  |     Start @bolyra/gateway on localhost:4100 --dev --target http://localhost:3001
  |     Send HTTP POST with JSON-RPC tools/call + Authorization header
  |     Verify: 200 response with correct result
  |     Send HTTP POST without Authorization
  |     Verify: 401/403 rejection
  |     Check receipts directory for generated receipts
```

## File Layout

```
examples/claude-desktop/
  README.md                    -- Step-by-step setup guide
  claude_desktop_config.json   -- Config snippet for Path A (stdio proxy)
  gateway.yaml                 -- Config snippet for Path B (gateway)
  setup.sh                     -- Install deps, build proxy, verify prereqs
  test-e2e.ts                  -- Automated E2E test (both paths)
  test-e2e.sh                  -- Shell wrapper: builds, runs test, reports
  upstream-server.ts           -- Minimal HTTP MCP server for Path B testing
  tsconfig.json                -- TypeScript config for the test files
  package.json                 -- Local package with test dependencies
```

## Detailed Design

### README.md

Sections:
1. **Prerequisites** -- Node 18+, Claude Desktop installed, repo cloned
2. **Path A: Stdio Proxy (Recommended for first try)**
   - Run `./setup.sh`
   - Copy `claude_desktop_config.json` snippet into Claude Desktop settings
   - Restart Claude Desktop
   - Try using any tool -- see Bolyra auth in Claude Desktop's MCP server logs
3. **Path B: HTTP Gateway**
   - Start upstream server: `node upstream-server.js`
   - Start gateway: `npx @bolyra/gateway --config gateway.yaml`
   - Configure Claude Desktop with gateway URL
   - Explain that this path requires a client-side auth shim (future work for full Desktop integration; the E2E test demonstrates the protocol)
4. **Automated Testing**
   - Run `./test-e2e.sh` to verify both paths without Claude Desktop
5. **Troubleshooting**
   - Common issues: rapidsnark binary missing, Node version, port conflicts

### claude_desktop_config.json

```json
{
  "mcpServers": {
    "bolyra-protected-fs": {
      "command": "node",
      "args": [
        "<REPO_ROOT>/examples/mcp-demo/dist/bolyra-proxy.js"
      ],
      "env": {
        "BOLYRA_RAPIDSNARK": "<REPO_ROOT>/circuits/build/rapidsnark_prover"
      }
    }
  }
}
```

The README will instruct users to replace `<REPO_ROOT>` with their actual path. The `setup.sh` script will offer to generate a fully-resolved version.

### gateway.yaml

```yaml
target: http://localhost:3001/mcp
port: 4100
devMode: true
receipts:
  enabled: true
  output: file
  dir: ./receipts/
health:
  enabled: true
  path: /healthz
```

### upstream-server.ts

A minimal HTTP MCP server that:
- Listens on port 3001
- Registers one tool: `echo` (takes `message: string`, returns it)
- Does NOT use Bolyra auth (auth is handled by the gateway in front)
- Uses `@modelcontextprotocol/sdk` server with HTTP transport

### test-e2e.ts

Test framework: plain Node.js `assert` + `child_process` (no external test runner -- keeps the example self-contained). Alternatively, uses the existing `mocha` setup if available in the monorepo.

**Path A tests:**
1. Spawn `bolyra-proxy` as child process with stdio pipes
2. Send `initialize` request, verify `initialize` response
3. Send `tools/list` request, verify `read_file` tool is listed
4. Send `tools/call` for `read_file` with a known file path, verify file contents returned
5. Verify stderr logs contain `[bolyra-proxy] proof for read_file` (proof was generated)

**Path B tests:**
1. Start upstream-server on port 3001
2. Start gateway on port 4100 with `--dev` flag
3. Send `initialize` request to gateway (should pass without auth -- exempt method)
4. Send `tools/call` without Authorization header (should be rejected)
5. Send `tools/call` with valid dev-mode Authorization (should be proxied and succeed)
6. Verify receipts directory has at least one receipt file
7. Hit `/healthz` endpoint, verify 200 response

### setup.sh

1. Check Node version >= 18
2. Check if `circuits/build/rapidsnark_prover` exists (warn if not -- tests still work but slower)
3. `cd examples/mcp-demo && npm install && npm run build` (builds bolyra-proxy.js)
4. `cd examples/claude-desktop && npm install`
5. Build test files: `npx tsc`
6. Generate resolved `claude_desktop_config.json` with actual repo root path
7. Print success message with next steps

### test-e2e.sh

1. Run `setup.sh` if not already done
2. Execute `node test-e2e.js`
3. Report pass/fail with clear output
4. Exit code 0 on all pass, 1 on any failure

## Dependencies

New dependencies for `examples/claude-desktop/package.json`:
- `@modelcontextprotocol/sdk` (for upstream-server.ts)
- `@bolyra/sdk` (for generating test proof bundles in Path B tests)
- `@bolyra/mcp` (for `attachBolyraProof` in Path B tests)
- `@bolyra/gateway` (for programmatic gateway startup in tests)
- `typescript` (dev)

All are already available in the monorepo. The example package.json will use workspace references or relative paths.

## Security Considerations

- The `claude_desktop_config.json` uses absolute paths. Users should not commit this file with their home directory paths.
- The demo uses hardcoded secrets (`DEMO_HUMAN_SECRET`, `DEMO_OPERATOR_KEY` in `shared.ts`). The README must prominently warn these are for demo only.
- The gateway `--dev` mode skips real ZKP verification. The README must explain this and how to switch to production mode.
- The test does not exercise real circuit proving to keep CI fast. The existing `test:circuits:slow` suite covers real proofs.

## Standards Impact

N/A -- no protocol/circuit changes. This is purely an integration test and documentation deliverable.

## Open Questions

None. The scope is well-defined: wrap existing working components in documentation and automated tests.
