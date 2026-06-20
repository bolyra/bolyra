/**
 * Minimal HTTP MCP server for Claude Desktop gateway path testing.
 *
 * Registers three tools: read_file, write_file, list_files.
 * Does NOT use Bolyra auth -- auth is handled by @bolyra/gateway in front.
 *
 * Can also run as stdio for proxy path testing when BOLYRA_TRANSPORT=stdio.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ---------- JSON-RPC types ----------

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

// ---------- Tool definitions ----------

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a file from disk and return its contents.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute or ~-relative path to read.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file on disk.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute or ~-relative path to write.' },
        content: { type: 'string', description: 'Content to write.' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'list_files',
    description: 'List files in a directory.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute or ~-relative directory path.' },
      },
      required: ['path'],
    },
  },
];

function expandPath(p: string): string {
  return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p;
}

async function handleToolCall(
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  switch (name) {
    case 'read_file': {
      const filePath = expandPath(args.path as string);
      const text = fs.readFileSync(filePath, 'utf8');
      return { content: [{ type: 'text', text }] };
    }
    case 'write_file': {
      const filePath = expandPath(args.path as string);
      fs.writeFileSync(filePath, args.content as string, 'utf8');
      return { content: [{ type: 'text', text: `Wrote ${(args.content as string).length} bytes to ${filePath}` }] };
    }
    case 'list_files': {
      const dirPath = expandPath(args.path as string);
      const entries = fs.readdirSync(dirPath);
      return { content: [{ type: 'text', text: entries.join('\n') }] };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---------- JSON-RPC dispatcher ----------

function handleRequest(req: JsonRpcRequest): JsonRpcResponse {
  const { id, method, params } = req;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'claude-desktop-example', version: '0.1.0' },
        },
      };

    case 'notifications/initialized':
      // Notification -- no response needed, but return empty result for consistency
      return { jsonrpc: '2.0', id, result: {} };

    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: TOOLS } };

    case 'tools/call': {
      const toolName = (params as Record<string, unknown>)?.name as string;
      const toolArgs = ((params as Record<string, unknown>)?.arguments ?? {}) as Record<string, unknown>;
      try {
        // Synchronous wrapper -- tools are sync in this demo
        const filePath = toolArgs.path as string | undefined;
        if (toolName === 'read_file' && filePath) {
          const expanded = expandPath(filePath);
          const text = fs.readFileSync(expanded, 'utf8');
          return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } };
        }
        if (toolName === 'write_file' && filePath) {
          const expanded = expandPath(filePath);
          fs.writeFileSync(expanded, toolArgs.content as string, 'utf8');
          return {
            jsonrpc: '2.0',
            id,
            result: { content: [{ type: 'text', text: `Wrote to ${expanded}` }] },
          };
        }
        if (toolName === 'list_files' && filePath) {
          const expanded = expandPath(filePath);
          const entries = fs.readdirSync(expanded);
          return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: entries.join('\n') }] } };
        }
        return {
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        };
      } catch (err: unknown) {
        return {
          jsonrpc: '2.0',
          id,
          error: { code: -32000, message: (err as Error).message },
        };
      }
    }

    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };

    default:
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

// ---------- HTTP mode ----------

function startHttp(port: number): http.Server {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as JsonRpcRequest;
        const response = handleRequest(body);
        const json = JSON.stringify(response);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(json),
        });
        res.end(json);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
      }
    });
  });

  server.listen(port, () => {
    process.stderr.write(`[claude-desktop-example] HTTP server listening on http://localhost:${port}\n`);
  });

  return server;
}

// ---------- Stdio mode ----------

function startStdio(): void {
  process.stderr.write('[claude-desktop-example] Starting in stdio mode\n');
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      try {
        const req = JSON.parse(line) as JsonRpcRequest;
        const resp = handleRequest(req);
        process.stdout.write(JSON.stringify(resp) + '\n');
      } catch {
        process.stdout.write(
          JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n',
        );
      }
    }
  });
}

// ---------- Entry point ----------

if (require.main === module) {
  const transport = process.env.BOLYRA_TRANSPORT ?? 'http';
  const port = parseInt(process.env.PORT ?? '3001', 10);

  if (transport === 'stdio') {
    startStdio();
  } else {
    startHttp(port);
  }
}

export { startHttp, startStdio, handleRequest, TOOLS };
