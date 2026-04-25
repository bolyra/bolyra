/**
 * HTTP / SSE / Streamable-HTTP transport wrapper.
 *
 * The spec-aligned path. MCP authorization (2025-03-26) tells servers to act
 * as OAuth 2.1 resource servers and expect `Authorization: Bearer <token>`.
 * We follow the same shape with a Bolyra-specific scheme:
 *
 *   Authorization: Bolyra <base64(JSON(BolyraProofBundle))>
 *
 * Custom auth schemes are valid per RFC 7235. Using a non-Bearer scheme
 * makes it explicit to OAuth-aware infrastructure that this is not an
 * opaque bearer token but a self-verifying ZKP credential — there is no
 * server-side secret to protect, so the threat model is different.
 *
 * The wrapper exposes an Express-compatible middleware. It validates the
 * Authorization header, attaches the BolyraAuthContext to req, and lets
 * the request proceed to the MCP HTTP transport. The transport then
 * passes the auth context through to handlers via `extra.authInfo`.
 */

import type {
  BolyraMcpHttpConfig,
  BolyraProofBundle,
  BolyraAuthContext,
} from './types';
import { verifyBundle, checkToolPolicy } from './verify';

/** Minimal Express-style req/res/next, kept loose so we don't pull express types. */
interface HttpReq {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: any;
  bolyra?: BolyraAuthContext;
}
interface HttpRes {
  status(code: number): HttpRes;
  setHeader(name: string, value: string): HttpRes;
  json(payload: unknown): void;
  end(): void;
}
type Next = (err?: unknown) => void;

const DEFAULT_SCHEME = 'Bolyra';

/**
 * Express/Connect-style middleware. Mount BEFORE your MCP HTTP transport
 * (e.g. SSEServerTransport, StreamableHTTPServerTransport) handler:
 *
 *   app.use('/mcp', bolyraAuthMiddleware(config));
 *   app.use('/mcp', myMcpTransport.handler);
 *
 * On success, `req.bolyra` is set to the BolyraAuthContext. Tool-call requests
 * also get checked against the per-tool policy by inspecting the JSON-RPC body.
 *
 * On failure, responds with 401 (no/invalid Authorization), 403 (permission
 * denied), or passes through (non-tool-call requests don't require auth — the
 * initialize/list_tools handshake is unauthenticated, matching OAuth resource-
 * server behavior where discovery is public).
 */
export function bolyraAuthMiddleware(config: BolyraMcpHttpConfig) {
  const scheme = config.authScheme ?? DEFAULT_SCHEME;
  const schemePrefix = `${scheme} `;

  return async (req: HttpReq, res: HttpRes, next: Next): Promise<void> => {
    // Only gate JSON-RPC tool calls. initialize / tools/list / notifications
    // are part of discovery and travel unauthenticated, mirroring how OAuth
    // resource servers expose .well-known/* without auth.
    const rpcMethod = extractJsonRpcMethod(req.body);
    if (rpcMethod !== 'tools/call') {
      return next();
    }

    const auth = headerString(req.headers['authorization']);
    if (!auth || !auth.startsWith(schemePrefix)) {
      respondWwwAuth(res, scheme, 'Bolyra auth required: missing Authorization header');
      return;
    }

    const encoded = auth.slice(schemePrefix.length).trim();
    let bundle: BolyraProofBundle;
    try {
      const json = Buffer.from(encoded, 'base64').toString('utf8');
      bundle = JSON.parse(json);
    } catch {
      respondWwwAuth(res, scheme, 'Bolyra auth failed: malformed bundle (expected base64-JSON)');
      return;
    }

    const authCtx = await verifyBundle(bundle, config);
    if (!authCtx.verified) {
      respondWwwAuth(res, scheme, `Bolyra auth failed: ${authCtx.reason ?? 'unknown'}`);
      return;
    }

    const toolName = extractToolName(req.body);
    if (toolName) {
      const policyErr = checkToolPolicy(toolName, authCtx, config);
      if (policyErr) {
        res.status(403).json({
          jsonrpc: '2.0',
          error: { code: -32001, message: `Bolyra policy denied: ${policyErr}` },
          id: req.body?.id ?? null,
        });
        return;
      }
    }

    req.bolyra = authCtx;
    next();
  };
}

/** Pull "tools/call" out of a JSON-RPC body. Defensive against shape variation. */
function extractJsonRpcMethod(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const m = (body as Record<string, unknown>).method;
  return typeof m === 'string' ? m : undefined;
}

function extractToolName(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const params = (body as Record<string, unknown>).params;
  if (!params || typeof params !== 'object') return undefined;
  const name = (params as Record<string, unknown>).name;
  return typeof name === 'string' ? name : undefined;
}

function headerString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function respondWwwAuth(res: HttpRes, scheme: string, message: string): void {
  res
    .status(401)
    .setHeader('WWW-Authenticate', `${scheme} realm="bolyra"`)
    .json({
      jsonrpc: '2.0',
      error: { code: -32000, message },
      id: null,
    });
}
