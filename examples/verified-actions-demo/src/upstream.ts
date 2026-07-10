/**
 * The upstream MCP server the gateway protects — a mock "payments" server
 * with two tools:
 *
 *   read_ledger      — read-only ledger lookup
 *   refund_customer  — mutating refund execution
 *
 * It never sees the Authorization header (the gateway consumes it). It DOES
 * see the X-Bolyra-* headers the gateway injects, so it can log verified
 * caller identity without importing any Bolyra code.
 */

import * as http from 'node:http';

export interface UpstreamOptions {
  log?: (line: string) => void;
}

interface JsonRpcBody {
  jsonrpc: '2.0';
  id?: string | number | null;
  method?: string;
  params?: { name?: string; arguments?: Record<string, unknown> };
}

export function createUpstreamServer(options: UpstreamOptions = {}): http.Server {
  const log = options.log ?? (() => {});

  return http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      let body: JsonRpcBody;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      }

      if (body.method !== 'tools/call') {
        return sendJson(res, 200, { jsonrpc: '2.0', id: body.id ?? null, result: {} });
      }

      const tool = body.params?.name;
      const args = body.params?.arguments ?? {};
      const did = header(req, 'x-bolyra-did');
      const receiptId = header(req, 'x-bolyra-receipt-id');

      let text: string;
      switch (tool) {
        case 'read_ledger':
          text = JSON.stringify({
            customer_id: args.customer_id,
            entries: [
              { date: '2026-07-01', description: 'Pro plan', amount_usd: -42.0 },
              { date: '2026-06-01', description: 'Pro plan', amount_usd: -42.0 },
            ],
          });
          break;
        case 'refund_customer':
          text = JSON.stringify({
            refund_id: 're_' + Math.random().toString(36).slice(2, 10),
            customer_id: args.customer_id,
            amount_usd: args.amount_usd,
            status: 'succeeded',
          });
          break;
        default:
          return sendJson(res, 200, {
            jsonrpc: '2.0',
            id: body.id ?? null,
            error: { code: -32602, message: `Unknown tool: ${tool}` },
          });
      }

      log(`executed ${tool} for ${did ?? 'unknown caller'} (X-Bolyra-Receipt-ID: ${receiptId ?? 'n/a'})`);
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id: body.id ?? null,
        result: { content: [{ type: 'text', text }] },
      });
    });
  });
}

function header(req: http.IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const raw = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) });
  res.end(raw);
}
