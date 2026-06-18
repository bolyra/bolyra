/**
 * @bolyra/gateway — auth middleware.
 *
 * Extracts Bolyra proof bundles from the Authorization header, verifies them
 * via @bolyra/mcp, and produces standard JSON-RPC error responses (401/403).
 *
 * Reuses verifyBundle() and checkToolPolicy() from @bolyra/mcp — no new
 * verification logic.
 */

import type { ServerResponse } from 'http';
import { verifyBundle, checkToolPolicy, MemoryNonceStore } from '@bolyra/mcp';
import type {
  BolyraProofBundle,
  BolyraAuthContext,
  BolyraMcpConfig,
  ToolPolicyMap,
} from '@bolyra/mcp';
import type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  GatewayRequest,
  JsonRpcError,
} from './types';

/**
 * Create gateway auth middleware. Returns an async function that verifies
 * the Authorization header and attaches BolyraAuthContext to the request.
 *
 * Returns true if the request is authorized, false if a response was already sent.
 */
export function createGatewayMiddleware(
  options: GatewayMiddlewareOptions,
): (req: GatewayRequest, res: ServerResponse, toolName?: string) => Promise<boolean> {
  const { config } = options;

  // Build the MCP config from gateway config
  const mcpConfig = buildMcpConfig(config, options);

  return async (req: GatewayRequest, res: ServerResponse, toolName?: string): Promise<boolean> => {
    const authHeader = headerString(req.headers['authorization']);

    if (!authHeader || !authHeader.startsWith('Bolyra ')) {
      sendJsonRpcError(res, 401, {
        jsonrpc: '2.0',
        id: req.jsonRpcBody?.id ?? null,
        error: {
          code: -32000,
          message: 'Bolyra auth required: missing or malformed Authorization header',
        },
      });
      return false;
    }

    const encoded = authHeader.slice('Bolyra '.length).trim();
    let bundle: BolyraProofBundle;
    try {
      const json = Buffer.from(encoded, 'base64').toString('utf8');
      bundle = JSON.parse(json);
    } catch {
      sendJsonRpcError(res, 401, {
        jsonrpc: '2.0',
        id: req.jsonRpcBody?.id ?? null,
        error: {
          code: -32000,
          message: 'Bolyra auth failed: malformed bundle (expected base64-encoded JSON)',
        },
      });
      return false;
    }

    // Verify the proof bundle
    const authCtx = await verifyBundle(bundle, mcpConfig);
    if (!authCtx.verified) {
      sendJsonRpcError(res, 401, {
        jsonrpc: '2.0',
        id: req.jsonRpcBody?.id ?? null,
        error: {
          code: -32000,
          message: `Bolyra auth failed: ${authCtx.reason ?? 'unknown'}`,
        },
      });
      return false;
    }

    // Check per-tool policy if tool name is known
    if (toolName) {
      const decision = checkToolPolicy(toolName, authCtx, mcpConfig);
      if (!decision.allowed) {
        sendJsonRpcError(res, 403, {
          jsonrpc: '2.0',
          id: req.jsonRpcBody?.id ?? null,
          error: {
            code: -32001,
            message: `Bolyra policy denied: ${decision.reason}`,
          },
        });
        return false;
      }
    }

    // Attach auth context to request
    req.bolyra = authCtx;
    return true;
  };
}

/** Build BolyraMcpConfig from GatewayConfig. */
function buildMcpConfig(
  config: GatewayConfig,
  options: GatewayMiddlewareOptions,
): BolyraMcpConfig {
  // Convert gateway tool policies (numbers) to MCP tool policies (bigints)
  let toolPolicy: ToolPolicyMap | undefined;
  if (config.tools) {
    toolPolicy = {};
    for (const [name, entry] of Object.entries(config.tools)) {
      toolPolicy[name] = {
        requireBitmask: entry.requireBitmask !== undefined ? BigInt(entry.requireBitmask) : undefined,
        minScore: entry.minScore,
        maxChainDepth: entry.maxChainDepth,
      };
    }
  }

  const mcpConfig: BolyraMcpConfig = {
    network: config.network,
    minScore: config.minScore,
    maxProofAge: config.nonce.maxProofAge,
    devMode: config.devMode,
    toolPolicy,
    nonceStore: options.nonceStore ?? new MemoryNonceStore(),
    receiptSigner: options.receiptSigner,
    resolveCredential: options.resolveCredential,
  };

  // In dev mode, resolveCredential is not required
  // In production, we need it — but @bolyra/mcp will throw if missing

  return mcpConfig;
}

/** Send a JSON-RPC error response. */
function sendJsonRpcError(
  res: ServerResponse,
  httpStatus: number,
  error: JsonRpcError,
): void {
  const body = JSON.stringify(error);
  if (httpStatus === 401) {
    res.setHeader('WWW-Authenticate', 'Bolyra realm="bolyra"');
  }
  res.writeHead(httpStatus, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/** Extract single string from header value. */
function headerString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/**
 * Extract tool name from a JSON-RPC tools/call body.
 */
export function extractToolName(body: Record<string, unknown> | undefined): string | undefined {
  if (!body) return undefined;
  const params = body.params;
  if (!params || typeof params !== 'object') return undefined;
  const name = (params as Record<string, unknown>).name;
  return typeof name === 'string' ? name : undefined;
}
