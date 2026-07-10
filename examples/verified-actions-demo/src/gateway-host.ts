/**
 * The verified-actions gateway host.
 *
 * This is @bolyra/gateway's documented embedding path ("Option 2: just the
 * middleware, for custom servers"): the exact createGatewayMiddleware that
 * powers `npx @bolyra/gateway` verifies every proof bundle (bundle shape,
 * credential authority, nonce replay), and the same checkToolPolicy from
 * @bolyra/mcp gates each tool. On top, this host signs an ES256K receipt for
 * EVERY decision — allow and deny — into the JSONL audit log.
 *
 * Four checks on every tools/call:
 *   1. proof bundle parse + verification + score  (createGatewayMiddleware)
 *   2. nonce replay protection                    (createGatewayMiddleware)
 *   3. credential binding — claimed permissions must match the registered
 *      credential (host registry; production: resolveCredential +
 *      scopeCommitment binding inside verifyBundle)
 *   4. per-tool permission policy                 (checkToolPolicy)
 * ...then: signed receipt -> audit log, X-Bolyra-* headers -> upstream.
 */

import * as http from 'node:http';
import { createGatewayMiddleware, extractToolName, injectBolyraHeaders } from '@bolyra/gateway';
import type { GatewayConfig, GatewayRequest } from '@bolyra/gateway';
import { checkToolPolicy } from '@bolyra/mcp';
import type { BolyraAuthContext, BolyraMcpConfig, BolyraProofBundle } from '@bolyra/mcp';
import type { AuthReceiptInput } from '@bolyra/receipts';
import { fmtMask } from './agents';
import type { AuditLog } from './audit';

const AUTH_EXEMPT = new Set(['initialize', 'notifications/initialized', 'ping']);

export interface HostOptions {
  config: GatewayConfig;
  audit: AuditLog;
  /**
   * Registered credentials: commitment (decimal string) -> granted permission
   * bitmask. Dev mode mocks proof verification, so the permission mask inside
   * the bundle is self-asserted; this registry is the server-side source of
   * truth the host checks claims against (the dev-mode stand-in for
   * production's resolveCredential + scopeCommitment binding, where a forged
   * mask is cryptographically impossible).
   */
  credentials: ReadonlyMap<string, bigint>;
  log?: (line: string) => void;
}

export function createVerifiedActionsHost(options: HostOptions): http.Server {
  const { config, audit } = options;
  const log = options.log ?? (() => {});

  // The shipped gateway middleware: verifyBundle + nonce store + 401 handling.
  const middleware = createGatewayMiddleware({ config });
  // Tool policy map for checkToolPolicy — same number->bigint conversion the
  // gateway's own middleware applies to config.tools internally.
  const policyConfig = buildPolicyConfig(config);
  const targetUrl = new URL(config.target);

  return http.createServer(async (incoming, res) => {
    const req = incoming as GatewayRequest;
    try {
      const rawBody = await readBody(req);
      req.rawBody = rawBody;

      let body: Record<string, unknown>;
      try {
        body = JSON.parse(rawBody.toString('utf8'));
      } catch {
        return sendJsonRpcError(res, 400, null, -32700, 'Parse error: malformed JSON-RPC body');
      }
      req.jsonRpcBody = body as unknown as GatewayRequest['jsonRpcBody'];
      const id = (body.id ?? null) as string | number | null;
      const method = typeof body.method === 'string' ? body.method : undefined;

      if (method && AUTH_EXEMPT.has(method)) {
        return await forward(req, res, targetUrl, {});
      }
      if (method !== 'tools/call') {
        return sendJsonRpcError(res, 404, id, -32601, 'Demo host only proxies tools/call (plus the MCP init handshake)');
      }

      const toolName = extractToolName(body);
      // Decode the bundle ourselves too: receipts bind the proof material,
      // so we need it on the deny path as well.
      const bundle = decodeBundle(req.headers['authorization']);

      // Checks 1-3. Passing no toolName defers the policy check to below so
      // deny receipts carry the full auth context (score, bitmask, DID).
      const authorized = await middleware(req, res, undefined);
      if (!authorized) {
        // Middleware already sent the 401 with the precise reason.
        log(`auth: proof bundle REJECTED for tool "${toolName ?? 'unknown'}" (replayed, malformed, or missing)`);
        const receipt = audit.record(
          bundle
            ? authFailInput(bundle, 'authentication_failed: proof bundle rejected by gateway (replayed, malformed, or expired)')
            : anonymousDenyInput('authentication_failed: no valid proof bundle presented'),
        );
        log(`receipt: signed deny receipt ${receipt.id} -> audit log`);
        return;
      }

      const authCtx = req.bolyra as BolyraAuthContext;
      log(`auth: proof bundle verified — score ${authCtx.score}/100, ${authCtx.did}`);

      if (!toolName || !bundle) {
        return sendJsonRpcError(res, 400, id, -32602, 'tools/call missing params.name');
      }

      // Credential binding. Dev mode trusts the bundle's claimed permission
      // mask, so cross-check it against the server-side registry — the same
      // role production's resolveCredential + Poseidon3 scopeCommitment
      // binding plays cryptographically (see integrations/mcp/src/verify.ts).
      const registered = options.credentials.get(bundle.credentialCommitment);
      if (registered === undefined || registered !== authCtx.permissionBitmask) {
        const reason =
          registered === undefined
            ? 'credential_unknown: commitment not registered with this gateway'
            : `credential_mismatch: bundle claims permissions ${fmtMask(authCtx.permissionBitmask)} but the registered credential grants ${fmtMask(registered)} (forged bundle)`;
        log(`auth: ${reason} -> DENIED`);
        const receipt = audit.record(decisionInput(bundle, authCtx, false, reason));
        log(`receipt: signed deny receipt ${receipt.id} -> audit log`);
        return sendJsonRpcError(res, 401, id, -32000, `Bolyra auth failed: ${reason}`);
      }

      // Check 4: per-tool permission policy.
      const decision = checkToolPolicy(toolName, authCtx, policyConfig);
      const required = requiredMask(policyConfig, toolName);
      const requiredText = required === undefined ? 'authenticated caller' : fmtMask(required);

      if (!decision.allowed) {
        log(`policy: "${toolName}" requires ${requiredText} — agent has ${fmtMask(authCtx.permissionBitmask)} -> DENIED`);
        const receipt = audit.record(decisionInput(bundle, authCtx, false, decision.reason ?? 'policy denied'));
        log(`receipt: signed deny receipt ${receipt.id} -> audit log`);
        return sendJsonRpcError(res, 403, id, -32001, `Bolyra policy denied: ${decision.reason}`);
      }

      log(`policy: "${toolName}" requires ${requiredText} — agent has ${fmtMask(authCtx.permissionBitmask)} -> ALLOWED`);
      const allowReason =
        `policy_allow: tool "${toolName}" requires ${required === undefined ? 'authentication only' : required.toString(2) + 'b'}, ` +
        `agent has ${authCtx.permissionBitmask.toString(2)}b`;
      const receipt = audit.record(decisionInput(bundle, authCtx, true, allowReason));
      log(`receipt: signed allow receipt ${receipt.id} -> audit log`);

      // Forward to the upstream with verified-identity headers (the upstream
      // never sees the Authorization header, only X-Bolyra-*).
      await forward(req, res, targetUrl, injectBolyraHeaders(authCtx, receipt.id));
    } catch (err) {
      log(`error: ${(err as Error).message}`);
      if (!res.headersSent) {
        sendJsonRpcError(res, 500, null, -32603, 'Internal demo host error');
      }
    }
  });
}

/** Same conversion buildMcpConfig applies inside the gateway middleware. */
function buildPolicyConfig(config: GatewayConfig): BolyraMcpConfig {
  const toolPolicy: NonNullable<BolyraMcpConfig['toolPolicy']> = {};
  for (const [name, entry] of Object.entries(config.tools ?? {})) {
    toolPolicy[name] = {
      requireBitmask: entry.requireBitmask !== undefined ? BigInt(entry.requireBitmask) : undefined,
      minScore: entry.minScore,
      maxChainDepth: entry.maxChainDepth,
    };
  }
  return { toolPolicy };
}

function requiredMask(policyConfig: BolyraMcpConfig, toolName: string): bigint | undefined {
  const raw = policyConfig.toolPolicy?.[toolName];
  if (raw === undefined) return undefined;
  return typeof raw === 'bigint' ? raw : raw.requireBitmask;
}

function decodeBundle(header: string | string[] | undefined): BolyraProofBundle | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value || !value.startsWith('Bolyra ')) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(value.slice('Bolyra '.length).trim(), 'base64').toString('utf8'));
    // Shape guard: receipts hash the proof material, so only accept bundles
    // that actually carry it. Anything else is treated as "no bundle".
    if (
      typeof parsed?.credentialCommitment !== 'string' ||
      typeof parsed?.nonce !== 'string' ||
      !Array.isArray(parsed?.humanProof?.publicSignals) ||
      !Array.isArray(parsed?.agentProof?.publicSignals)
    ) {
      return undefined;
    }
    return parsed as BolyraProofBundle;
  } catch {
    return undefined;
  }
}

/** Receipt input for a decision made with a verified auth context. */
function decisionInput(
  bundle: BolyraProofBundle,
  authCtx: BolyraAuthContext,
  allowed: boolean,
  reasonCode: string,
): AuthReceiptInput {
  return {
    rootDid: authCtx.did,
    actingDid: authCtx.did,
    credentialCommitment: bundle.credentialCommitment,
    effectiveCommitment: authCtx.effectiveCommitment,
    allowed,
    reasonCode,
    score: authCtx.score,
    permissionBitmask: authCtx.permissionBitmask.toString(),
    chainDepth: authCtx.chainDepth,
    humanProof: bundle.humanProof,
    agentProof: bundle.agentProof,
    humanPublicSignals: bundle.humanProof.publicSignals,
    agentPublicSignals: bundle.agentProof.publicSignals,
    bundleVersion: bundle.v,
    nonce: bundle.nonce,
    delegationChain: bundle.delegationChain,
  };
}

/** Receipt input for a bundle the gateway rejected outright (no auth context). */
function authFailInput(bundle: BolyraProofBundle, reasonCode: string): AuthReceiptInput {
  const commitmentHex = safeCommitmentHex(bundle.credentialCommitment);
  const did = `did:bolyra:dev:${commitmentHex}`;
  return {
    rootDid: did,
    actingDid: did,
    credentialCommitment: bundle.credentialCommitment,
    effectiveCommitment: bundle.credentialCommitment,
    allowed: false,
    reasonCode,
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: bundle.humanProof,
    agentProof: bundle.agentProof,
    humanPublicSignals: bundle.humanProof.publicSignals,
    agentPublicSignals: bundle.agentProof.publicSignals,
    bundleVersion: bundle.v,
    nonce: bundle.nonce,
    delegationChain: bundle.delegationChain,
  };
}

/**
 * Receipt input for a request with no usable proof bundle at all (missing or
 * malformed Authorization header). Even anonymous rejections leave a signed
 * record.
 */
function anonymousDenyInput(reasonCode: string): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:dev:anonymous',
    actingDid: 'did:bolyra:dev:anonymous',
    credentialCommitment: '0',
    effectiveCommitment: '0',
    allowed: false,
    reasonCode,
    score: 0,
    permissionBitmask: '0',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce: '0',
  };
}

function safeCommitmentHex(commitment: string): string {
  try {
    return BigInt(commitment).toString(16).padStart(64, '0');
  } catch {
    return 'unparseable';
  }
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 1_048_576) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function forward(
  req: GatewayRequest,
  res: http.ServerResponse,
  targetUrl: URL,
  extraHeaders: Record<string, string>,
): Promise<void> {
  const upstream = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...extraHeaders },
    body: new Uint8Array(req.rawBody ?? Buffer.alloc(0)),
  });
  const text = await upstream.text();
  res.writeHead(upstream.status, { 'content-type': 'application/json' });
  res.end(text);
}

function sendJsonRpcError(
  res: http.ServerResponse,
  httpStatus: number,
  id: string | number | null,
  code: number,
  message: string,
): void {
  const body = JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
  res.writeHead(httpStatus, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}
