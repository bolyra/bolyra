/**
 * @bolyra/gateway — reverse proxy core.
 *
 * HTTP reverse proxy using native Node.js http/https.request.
 * Routes requests based on JSON-RPC method:
 * - GET {healthPath} -> health handler
 * - JSON-RPC method != "tools/call" -> forward without auth
 * - JSON-RPC method == "tools/call" -> auth middleware, then forward
 */

import * as http from 'http';
import * as https from 'https';
import { createGatewayMiddleware, extractToolName } from './middleware';
import { injectBolyraHeaders, computeHmac } from './headers';
import { createHealthHandler } from './health';
import { createReceiptWriter } from './receipts';
import type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  GatewayRequest,
  JsonRpcRequest,
  ReceiptWriter,
} from './types';
import type { BolyraAuthContext } from '@bolyra/mcp';

/** Options for createGatewayProxy. */
export interface GatewayProxyOptions extends GatewayMiddlewareOptions {
  /** Custom receipt writer (overrides config-based writer). */
  receiptWriter?: ReceiptWriter;
}

/**
 * Create and return an HTTP server that acts as a reverse proxy with
 * Bolyra auth gating on tools/call requests.
 */
export function createGatewayProxy(options: GatewayProxyOptions): http.Server {
  const { config } = options;
  const targetUrl = new URL(config.target);
  const isTargetHttps = targetUrl.protocol === 'https:';

  // Create components
  const authMiddleware = createGatewayMiddleware(options);
  const healthHandler = createHealthHandler(config);
  const receiptWriter = options.receiptWriter ?? createReceiptWriter(config.receipts);

  const server = http.createServer(async (incomingReq, res) => {
    const req = incomingReq as GatewayRequest;

    try {
      // Health check intercept
      if (config.health.enabled && req.method === 'GET' && req.url === config.health.path) {
        await healthHandler(req, res);
        return;
      }

      // Read the full body for JSON-RPC parsing
      const rawBody = await readBody(req);
      req.rawBody = rawBody;

      // Parse JSON-RPC body
      let jsonRpcBody: JsonRpcRequest | undefined;
      if (rawBody.length > 0) {
        try {
          const parsed = JSON.parse(rawBody.toString('utf-8'));

          // Reject batch requests (arrays)
          if (Array.isArray(parsed)) {
            sendJsonRpcError(res, 400, null, -32600, 'JSON-RPC batch requests are not supported');
            return;
          }

          jsonRpcBody = parsed as JsonRpcRequest;
          req.jsonRpcBody = jsonRpcBody;
        } catch {
          sendJsonRpcError(res, 400, null, -32700, 'Parse error: malformed JSON-RPC body');
          return;
        }
      }

      // Determine if this is a tools/call that needs auth
      const isToolsCall = jsonRpcBody?.method === 'tools/call';

      if (isToolsCall) {
        // Extract tool name for policy check
        const toolName = extractToolName(jsonRpcBody as unknown as Record<string, unknown>);

        // Run auth middleware
        const authorized = await authMiddleware(req, res, toolName);
        if (!authorized) {
          // Middleware already sent response
          // Write denial receipt
          writeReceiptForDenial(receiptWriter, jsonRpcBody, toolName);
          return;
        }

        // Write allow receipt
        writeReceiptForAllow(receiptWriter, req.bolyra!, jsonRpcBody, toolName);
      }

      // Forward request to upstream
      await forwardRequest(req, res, targetUrl, isTargetHttps, config);
    } catch (err) {
      console.error('[gateway] unhandled error:', err);
      if (!res.headersSent) {
        sendJsonRpcError(res, 502, req.jsonRpcBody?.id ?? null, -32603, 'Internal gateway error');
      }
    }
  });

  return server;
}

/** Read the full request body into a buffer. */
function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Forward the request to the upstream server. */
function forwardRequest(
  req: GatewayRequest,
  res: http.ServerResponse,
  targetUrl: URL,
  isTargetHttps: boolean,
  config: GatewayConfig,
): Promise<void> {
  return new Promise((resolve) => {
    // Build forwarded headers — copy all except Authorization and Host
    const forwardHeaders: Record<string, string | string[] | undefined> = { ...req.headers };
    delete forwardHeaders['authorization']; // Consumed by gateway
    delete forwardHeaders['host']; // Will be rewritten
    forwardHeaders['host'] = targetUrl.host;

    // Inject X-Bolyra-* headers for authenticated requests
    if (req.bolyra) {
      const receiptId = req.bolyra.receipt?.payload
        ? (req.bolyra.receipt.payload as unknown as Record<string, string>).receiptId
        : undefined;
      const bolyraHeaders = injectBolyraHeaders(req.bolyra, receiptId);

      // HMAC sign if configured
      if (config.hmac?.secret) {
        const hmacValue = computeHmac(bolyraHeaders, config.hmac.secret);
        bolyraHeaders['X-Bolyra-HMAC'] = hmacValue;
      }

      Object.assign(forwardHeaders, bolyraHeaders);
    }

    // Set content-length from raw body
    if (req.rawBody) {
      forwardHeaders['content-length'] = String(req.rawBody.length);
    }

    const requestFn = isTargetHttps ? https.request : http.request;
    const proxyReq = requestFn(
      {
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isTargetHttps ? 443 : 80),
        path: targetUrl.pathname + (targetUrl.search || ''),
        method: req.method,
        headers: forwardHeaders as http.OutgoingHttpHeaders,
        timeout: 30000,
      },
      (proxyRes) => {
        // Forward upstream status and headers
        res.writeHead(proxyRes.statusCode!, proxyRes.headers);
        proxyRes.pipe(res);
        proxyRes.on('end', resolve);
      },
    );

    proxyReq.on('error', (err) => {
      console.error('[gateway] upstream error:', err.message);
      if (!res.headersSent) {
        sendJsonRpcError(res, 502, req.jsonRpcBody?.id ?? null, -32000, `Bad Gateway: upstream connection failed (${err.message})`);
      }
      resolve();
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      if (!res.headersSent) {
        sendJsonRpcError(res, 502, req.jsonRpcBody?.id ?? null, -32000, 'Bad Gateway: upstream timeout');
      }
      resolve();
    });

    // Send the raw body
    if (req.rawBody && req.rawBody.length > 0) {
      proxyReq.write(req.rawBody);
    }
    proxyReq.end();
  });
}

/** Send a JSON-RPC error response. */
function sendJsonRpcError(
  res: http.ServerResponse,
  httpStatus: number,
  id: string | number | null | undefined,
  code: number,
  message: string,
): void {
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: id ?? null,
    error: { code, message },
  });
  res.writeHead(httpStatus, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/** Write a receipt for a denied request. */
function writeReceiptForDenial(
  writer: ReceiptWriter,
  body: JsonRpcRequest | undefined,
  toolName: string | undefined,
): void {
  writer.writeRaw({
    decision: 'deny',
    toolName: toolName ?? 'unknown',
    method: body?.method ?? 'unknown',
    timestamp: new Date().toISOString(),
  });
}

/** Write a receipt for an allowed request. */
function writeReceiptForAllow(
  writer: ReceiptWriter,
  authCtx: BolyraAuthContext,
  body: JsonRpcRequest | undefined,
  toolName: string | undefined,
): void {
  if (authCtx.receipt) {
    writer.write(authCtx.receipt);
  } else {
    writer.writeRaw({
      decision: 'allow',
      toolName: toolName ?? 'unknown',
      method: body?.method ?? 'unknown',
      did: authCtx.did,
      score: authCtx.score,
      timestamp: new Date().toISOString(),
    });
  }
}
