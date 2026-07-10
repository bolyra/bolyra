/**
 * @bolyra/gateway — reverse proxy core.
 *
 * HTTP reverse proxy using native Node.js http/https.request.
 * Routes requests based on JSON-RPC method:
 * - GET {healthPath} -> health handler
 * - Auth-exempt methods (initialize, notifications/initialized, ping) -> forward without auth
 * - All other methods -> auth middleware (verifyBundle), then forward
 * - tools/call -> additionally checks per-tool policy (checkToolPolicy)
 */

import * as http from 'http';
import * as https from 'https';
import { createGatewayMiddleware, extractToolName } from './middleware';
import { injectBolyraHeaders, computeHmac } from './headers';
import { createHealthHandler } from './health';
import { createReceiptWriter } from './receipts';
import {
  createGatewayReceiptSigner,
  buildDecisionReceiptInput,
  buildDenialReceiptInput,
} from './receipt-signer';
import type { GatewayReceiptSigner } from './receipt-signer';
import type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  GatewayRequest,
  JsonRpcRequest,
  ReceiptWriter,
} from './types';
import type { BolyraAuthContext } from '@bolyra/mcp';
import { hasStaticCredentials } from './credential-binding';

/** Options for createGatewayProxy. */
export interface GatewayProxyOptions extends GatewayMiddlewareOptions {
  /** Custom receipt writer (overrides config-based writer). */
  receiptWriter?: ReceiptWriter;
  /**
   * Pre-resolved gateway receipt signer (overrides receiptSigner/config).
   * Used by the CLI so the proxy signs with the exact key whose address was
   * printed in the banner and persisted to signer.json.
   */
  gatewayReceiptSigner?: GatewayReceiptSigner;
}

/**
 * Create and return an HTTP server that acts as a reverse proxy with
 * Bolyra auth gating on tools/call requests.
 */
export function createGatewayProxy(options: GatewayProxyOptions): http.Server {
  const { config } = options;
  const targetUrl = new URL(config.target);
  const isTargetHttps = targetUrl.protocol === 'https:';

  // Create components.
  // Receipts are active when either the config enables them or the caller
  // injected a writer. When active, EVERY tools/call decision — allow and
  // deny, dev and production — is ES256K-signed by the gateway's own signer,
  // which carries the FINAL decision (including the tool-policy verdict).
  // The middleware deliberately gets no receiptSigner: a receipt attached by
  // @bolyra/mcp's verifyBundle records only the verification step, so for a
  // request that authenticates but fails tool policy it would say
  // allowed=true while the gateway returned 403.
  const receiptsActive = options.receiptWriter !== undefined || config.receipts.enabled;
  const receiptSigner =
    options.gatewayReceiptSigner ??
    (receiptsActive ? createGatewayReceiptSigner(config, options.receiptSigner) : undefined);
  const authMiddleware = createGatewayMiddleware({ ...options, receiptSigner: undefined });
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
      const rawBody = await readBody(req, config.maxBodySize);
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

      // Methods exempt from auth (initialization handshake + keep-alive)
      const AUTH_EXEMPT_METHODS = new Set(['initialize', 'notifications/initialized', 'ping']);
      const method = jsonRpcBody?.method;
      const isAuthExempt = !method || AUTH_EXEMPT_METHODS.has(method);
      const isToolsCall = method === 'tools/call';

      if (!isAuthExempt) {
        // Extract tool name for policy check (only meaningful for tools/call)
        const toolName = isToolsCall
          ? extractToolName(jsonRpcBody as unknown as Record<string, unknown>)
          : undefined;

        // Run auth middleware (verifyBundle for all; checkToolPolicy only for tools/call)
        const authorized = await authMiddleware(req, res, isToolsCall ? toolName : undefined);
        if (!authorized) {
          // Middleware already sent response
          if (isToolsCall) {
            writeReceiptForDenial(receiptWriter, receiptSigner, config, req, jsonRpcBody, toolName);
          }
          return;
        }

        // Write allow receipt for tools/call
        if (isToolsCall) {
          writeReceiptForAllow(receiptWriter, receiptSigner, config, req, jsonRpcBody, toolName);
        }
      }

      // Forward request to upstream
      await forwardRequest(req, res, targetUrl, isTargetHttps, config);
    } catch (err) {
      if ((err as any)?.statusCode === 413) {
        if (!res.headersSent) {
          sendJsonRpcError(res, 413, null, -32600, 'Request body too large');
        }
      } else {
        console.error('[gateway] unhandled error:', err);
        if (!res.headersSent) {
          sendJsonRpcError(res, 502, req.jsonRpcBody?.id ?? null, -32603, 'Internal gateway error');
        }
      }
    }
  });

  return server;
}

/** Read the full request body into a buffer, enforcing a size limit. */
function readBody(req: http.IncomingMessage, maxBodySize: number = 1_048_576): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBodySize) {
        req.destroy(new Error('Request body too large'));
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    });
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

    // Strip ALL incoming X-Bolyra-* headers to prevent spoofing
    for (const key of Object.keys(forwardHeaders)) {
      if (/^x-bolyra-/i.test(key)) {
        delete forwardHeaders[key];
      }
    }
    forwardHeaders['host'] = targetUrl.host;

    // Inject X-Bolyra-* headers for authenticated requests
    if (req.bolyra) {
      const receiptId = req.bolyra.receipt?.id;
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
        sendJsonRpcError(res, 502, req.jsonRpcBody?.id ?? null, -32000, 'Bad Gateway: upstream connection failed');
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

/**
 * Write an ES256K-signed receipt for a denied request. Falls back to the
 * legacy unsigned raw record only if signing itself fails — receipt problems
 * must never break request handling.
 */
function writeReceiptForDenial(
  writer: ReceiptWriter,
  signer: GatewayReceiptSigner | undefined,
  config: GatewayConfig,
  req: GatewayRequest,
  body: JsonRpcRequest | undefined,
  toolName: string | undefined,
): void {
  const denial = req.bolyraDenial;
  let signingError: string | undefined;
  if (signer) {
    try {
      writer.write(signer.sign(buildDenialReceiptInput(denial, config, toolName)));
      return;
    } catch (err) {
      signingError = (err as Error).message;
      console.error('[gateway] deny receipt signing error:', signingError);
    }
  }
  // Last-resort record. Explicitly tagged so audit consumers can detect the
  // gap — a signed receipt cannot be forged from this. (The signing key is
  // probe-validated at startup, so reaching this at runtime is exceptional.)
  writer.writeRaw({
    unsigned: true,
    ...(signingError ? { signingError } : {}),
    decision: 'deny',
    toolName: toolName ?? 'unknown',
    method: body?.method ?? 'unknown',
    reason: denial?.reason,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Write an ES256K-signed receipt for an allowed request and attach it to the
 * auth context so the X-Bolyra-Receipt-ID header can reference it. Falls back
 * to the legacy unsigned raw record only if signing fails.
 */
function writeReceiptForAllow(
  writer: ReceiptWriter,
  signer: GatewayReceiptSigner | undefined,
  config: GatewayConfig,
  req: GatewayRequest,
  body: JsonRpcRequest | undefined,
  toolName: string | undefined,
): void {
  const authCtx = req.bolyra!;
  let signingError: string | undefined;
  if (signer) {
    try {
      const receipt = signer.sign(buildAllowInput(req, authCtx, config, toolName));
      // Cast: @bolyra/mcp pins an older @bolyra/receipts whose SignedReceipt
      // predates the 'bolyra.commerce' kind — structurally identical for auth.
      authCtx.receipt = receipt as unknown as NonNullable<BolyraAuthContext['receipt']>; // X-Bolyra-Receipt-ID references this
      writer.write(receipt);
      return;
    } catch (err) {
      signingError = (err as Error).message;
      console.error('[gateway] allow receipt signing error:', signingError);
    }
  }
  // Last-resort record, tagged so audit consumers can detect the gap.
  writer.writeRaw({
    unsigned: true,
    ...(signingError ? { signingError } : {}),
    decision: 'allow',
    toolName: toolName ?? 'unknown',
    method: body?.method ?? 'unknown',
    did: authCtx.did,
    score: authCtx.score,
    timestamp: new Date().toISOString(),
  });
}

/** Build the receipt input for an allow decision (same shape the demo emits). */
function buildAllowInput(
  req: GatewayRequest,
  authCtx: BolyraAuthContext,
  config: GatewayConfig,
  toolName: string | undefined,
): import('@bolyra/receipts').AuthReceiptInput {
  const required = toolName !== undefined ? config.tools?.[toolName]?.requireBitmask : undefined;
  let reason =
    `policy_allow: tool "${toolName ?? 'unknown'}" requires ` +
    `${required === undefined ? 'authentication only' : required.toString(2) + 'b'}, ` +
    `agent has ${authCtx.permissionBitmask.toString(2)}b`;
  // Unbound dev mode: no credential registry, so the permission claim was
  // taken at face value. Flag it on the receipt itself (the same
  // make-the-tradeoff-visible pattern as 0.3.0's ephemeral-signer marking).
  if (config.devMode && !hasStaticCredentials(config.credentials)) {
    reason += ' [credential-binding: none — permission claims self-asserted]';
  }
  const bundle = req.bolyraBundle;
  if (bundle) {
    return buildDecisionReceiptInput(bundle, authCtx, config, true, reason);
  }
  // Verified without receiptable proof material (custom embeddings) — still
  // leave a signed record of the decision.
  return {
    rootDid: authCtx.did,
    actingDid: authCtx.did,
    credentialCommitment: authCtx.effectiveCommitment || '0',
    effectiveCommitment: authCtx.effectiveCommitment || '0',
    allowed: true,
    reasonCode: reason,
    score: authCtx.score,
    permissionBitmask: authCtx.permissionBitmask.toString(),
    chainDepth: authCtx.chainDepth,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce: '0',
  };
}
