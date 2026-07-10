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
import { isReceiptableBundle } from './receipt-signer';
import {
  buildCredentialRegistry,
  checkCredentialBinding,
  createStaticCredentialResolver,
} from './credential-binding';

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

  // Dev-mode credential binding registry (packaged check 3). Dev proofs are
  // mocked, so when credentials are configured the claimed mask MUST match
  // the registered grant. Built once at startup — a malformed map fails here,
  // not mid-request. Production binding happens inside verifyBundle instead
  // (resolveCredential + Poseidon3 scopeCommitment).
  const devCredentialRegistry = config.devMode
    ? buildCredentialRegistry(config.credentials)
    : undefined;

  return async (req: GatewayRequest, res: ServerResponse, toolName?: string): Promise<boolean> => {
    const authHeader = headerString(req.headers['authorization']);

    if (!authHeader || !authHeader.startsWith('Bolyra ')) {
      const reason = 'missing or malformed Authorization header';
      req.bolyraDenial = { stage: 'missing_auth', reason: `authentication_failed: ${reason}` };
      sendJsonRpcError(res, 401, {
        jsonrpc: '2.0',
        id: req.jsonRpcBody?.id ?? null,
        error: {
          code: -32000,
          message: `Bolyra auth required: ${reason}`,
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
      req.bolyraDenial = {
        stage: 'malformed_bundle',
        reason: 'authentication_failed: malformed bundle (expected base64-encoded JSON)',
      };
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

    // Expose the bundle for receipt signing only when it carries the proof
    // material receipts hash. A shapeless bundle gets an anonymous receipt.
    if (isReceiptableBundle(bundle)) {
      req.bolyraBundle = bundle;
    }

    // Verify the proof bundle. verifyBundle can throw on bundles that parse
    // as JSON but are missing proof material entirely — fail closed with a
    // 401 (and a recorded denial) rather than bubbling into a 502.
    let authCtx: BolyraAuthContext;
    try {
      authCtx = await verifyBundle(bundle, mcpConfig);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      req.bolyraDenial = {
        stage: 'verification_failed',
        reason: `authentication_failed: proof bundle verification threw: ${message}`,
        bundle: req.bolyraBundle,
      };
      sendJsonRpcError(res, 401, {
        jsonrpc: '2.0',
        id: req.jsonRpcBody?.id ?? null,
        error: {
          code: -32000,
          message: 'Bolyra auth failed: proof bundle could not be verified',
        },
      });
      return false;
    }
    if (!authCtx.verified) {
      req.bolyraDenial = {
        stage: 'verification_failed',
        reason: `authentication_failed: ${authCtx.reason ?? 'unknown'}`,
        authCtx,
        bundle: req.bolyraBundle,
      };
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

    // Dev-mode credential binding: the claimed identity/permissions must
    // match the registered credential. Mismatch is an authentication failure
    // — fail closed with 401, and record the denial so the proxy signs a
    // deny receipt whose reasonCode names the mismatch class.
    if (devCredentialRegistry) {
      const binding = checkCredentialBinding(bundle, authCtx, devCredentialRegistry);
      if (!binding.ok) {
        req.bolyraDenial = {
          stage: 'credential_binding_failed',
          reason: binding.reasonCode,
          authCtx,
          bundle: req.bolyraBundle,
        };
        sendJsonRpcError(res, 401, {
          jsonrpc: '2.0',
          id: req.jsonRpcBody?.id ?? null,
          error: {
            code: -32000,
            message: `Bolyra auth failed: ${binding.reasonCode}`,
          },
        });
        return false;
      }
    }

    // Check per-tool policy if tool name is known
    if (toolName) {
      const decision = checkToolPolicy(toolName, authCtx, mcpConfig);
      if (!decision.allowed) {
        req.bolyraDenial = {
          stage: 'policy_denied',
          reason: `policy_denied: ${decision.reason ?? 'tool policy denied'}`,
          authCtx,
          bundle: req.bolyraBundle,
        };
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
    // Explicit resolver (library embedders) wins; otherwise static
    // credentials from the config become the production resolver, engaging
    // verifyBundle's Poseidon3 scopeCommitment binding.
    resolveCredential:
      options.resolveCredential ?? createStaticCredentialResolver(config.credentials),
  };

  // In dev mode, resolveCredential is not required (binding is enforced by
  // the gateway's own registry check when credentials are configured).
  // In production, verifyBundle throws without it — fail closed per request.

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
