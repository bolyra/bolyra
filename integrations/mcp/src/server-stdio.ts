/**
 * stdio transport server wrapper.
 *
 * MCP's spec defines no transport-layer auth for stdio — the host that spawns
 * the server is the trust boundary. We layer Bolyra on top by reading the
 * proof bundle from `params._meta.bolyra` on every `tools/call` request.
 *
 * This is the path Claude Desktop / Cursor / Cline use today, and the most
 * visceral demo target: any third-party stdio MCP server can drop this in
 * and refuse calls from unverified agents.
 */

import type { BolyraMcpConfig, BolyraProofBundle, BolyraAuthContext } from './types';
import { verifyBundle, checkToolPolicy } from './verify';

/**
 * Minimal MCP low-level Server surface we need. The real SDK's
 * `Server.setRequestHandler<T extends ZodSchema>(schema: T, handler)` keys its
 * internal map off `schema.shape.method.value`, so we have to pass a real Zod
 * schema (not a method-name string). We intentionally don't import the SDK
 * type so this package builds cleanly across SDK versions; the schema is
 * supplied dynamically below via `loadCallToolRequestSchema`.
 */
interface McpServerLike {
  setRequestHandler(
    schema: any,
    handler: (request: any, extra: any) => Promise<any>,
  ): void;
}

/**
 * Wrap an MCP server (stdio transport) so every `tools/call` requires a valid
 * Bolyra proof bundle in `params._meta.bolyra`.
 *
 * Returns the same server reference (mutated). The user-supplied tool handlers
 * registered via `server.registerTool(...)` are NOT touched — the gate sits at
 * the protocol layer below them via `setRequestHandler('tools/call', ...)`.
 *
 * IMPORTANT: call this BEFORE any user `registerTool` calls, because
 * setRequestHandler for the same method is last-write-wins in the MCP SDK.
 * If you need to register tools after wrapping, use `wrap()` style:
 *
 *   const server = new McpServer({...});
 *   server.registerTool('read_file', ..., handler);
 *   withBolyraAuthStdio(server, config); // ← call after registration
 *
 * The wrapper captures the previously-registered handler and chains.
 */
export function withBolyraAuthStdio<T extends McpServerLike>(
  server: T,
  config: BolyraMcpConfig,
): T {
  // Snapshot whatever handler the McpServer already installed for tools/call.
  // The high-level McpServer registers one when you call registerTool() — it
  // dispatches by tool name. We need to call into that after auth succeeds.
  const innerHandler = captureExistingHandler(server, 'tools/call');

  if (!innerHandler) {
    throw new Error(
      '@bolyra/mcp: no tools/call handler found on server. Call registerTool() before withBolyraAuthStdio().',
    );
  }

  const callToolSchema = loadCallToolRequestSchema(config);
  server.setRequestHandler(callToolSchema, async (request: any, extra: any) => {
    const bundle: BolyraProofBundle | undefined = request?.params?._meta?.bolyra;

    if (!bundle) {
      return mcpError(
        'Bolyra auth required: missing proof bundle in params._meta.bolyra',
      );
    }

    const authCtx = await verifyBundle(bundle, config);
    if (!authCtx.verified) {
      return mcpError(`Bolyra auth failed: ${authCtx.reason ?? 'unknown reason'}`);
    }

    const toolName: string = request?.params?.name ?? '';
    const policyErr = checkToolPolicy(toolName, authCtx, config);
    if (policyErr) {
      return mcpError(`Bolyra policy denied: ${policyErr}`);
    }

    // Hand off to the user's handler with the auth context attached.
    const enrichedExtra = {
      ...extra,
      authInfo: { ...(extra?.authInfo ?? {}), bolyra: authCtx satisfies BolyraAuthContext },
    };
    return innerHandler(request, enrichedExtra);
  });

  return server;
}

/**
 * Best-effort handler capture. The MCP SDK keeps handlers in an internal map
 * keyed by method. We try a couple of conventional shapes and fall back to
 * `undefined` (the wrapper will throw with a clear error).
 */
function captureExistingHandler(
  server: any,
  method: string,
): ((req: any, extra: any) => Promise<any>) | undefined {
  // Common shapes across MCP SDK versions.
  const candidates = [
    server?._requestHandlers?.get?.(method),
    server?.requestHandlers?.get?.(method),
    server?.server?._requestHandlers?.get?.(method),
    server?.server?.requestHandlers?.get?.(method),
  ];
  return candidates.find((h) => typeof h === 'function');
}

/**
 * Resolve the CallToolRequestSchema. We prefer an injected schema (caller
 * passes it via config when running under bundlers / ESM that can't `require`
 * the SDK), else fall back to a synchronous require of the peer-dep SDK.
 */
function loadCallToolRequestSchema(config: BolyraMcpConfig): unknown {
  if (config.callToolRequestSchema) return config.callToolRequestSchema;
  // The SDK is a peer dep — it lives in the consumer's node_modules, not in
  // ours. When this package is linked via `file:` (or installed normally with
  // npm 7+ peer hoisting), Node's default resolution from __filename may walk
  // a tree that doesn't include the consumer. Resolve from process.cwd() so
  // we land in the consumer's tree, then fall back to local require.
  /* eslint-disable @typescript-eslint/no-var-requires */
  const { createRequire } = require('node:module');
  const path = require('node:path');
  let types: any;
  try {
    const reqFromCwd = createRequire(path.join(process.cwd(), 'index.js'));
    types = reqFromCwd('@modelcontextprotocol/sdk/types.js');
  } catch {
    types = require('@modelcontextprotocol/sdk/types.js');
  }
  /* eslint-enable @typescript-eslint/no-var-requires */
  if (!types?.CallToolRequestSchema) {
    throw new Error(
      '@bolyra/mcp: CallToolRequestSchema not found. Pass it via config.callToolRequestSchema.',
    );
  }
  return types.CallToolRequestSchema;
}

/** Build the MCP-spec error response shape for tool calls. */
function mcpError(message: string) {
  return {
    isError: true,
    content: [{ type: 'text', text: message }],
  };
}
