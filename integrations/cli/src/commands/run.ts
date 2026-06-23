/**
 * bolyra run — spawn a stdio MCP server, wrap with Shield (auth),
 * expose over HTTP via Gateway. One command, production-ready.
 *
 * Usage:
 *   bolyra run -- npx @modelcontextprotocol/server-filesystem /tmp
 *   bolyra run --port 8787 --dev -- node my-server.js
 *   bolyra run --policy shield.yaml -- npx some-mcp-server
 */

import { spawn, ChildProcess } from 'child_process';
import * as http from 'http';
import * as readline from 'readline';
import { parseArgs } from 'node:util';

const HELP = `
bolyra run — run any stdio MCP server with auth + HTTP exposure

Usage:
  bolyra run [options] -- <server command>

Options:
  --port <n>       HTTP port (default: 4100)
  --dev            Dev mode (mock verification, no real ZKP)
  --policy <path>  Shield policy YAML file
  --help           Show this help

Examples:
  bolyra run -- npx @modelcontextprotocol/server-filesystem /tmp
  bolyra run --port 8787 --dev -- node my-server.js
  bolyra run --policy shield.yaml -- npx some-mcp-server
`.trim();

export async function run(argv: string[]): Promise<void> {
  // Split on '--' to separate bolyra args from server command
  const dashIdx = argv.indexOf('--');
  const bolyraArgs = dashIdx >= 0 ? argv.slice(0, dashIdx) : argv;
  const serverArgs = dashIdx >= 0 ? argv.slice(dashIdx + 1) : [];

  let parsed;
  try {
    parsed = parseArgs({
      args: bolyraArgs,
      options: {
        port: { type: 'string', default: '4100' },
        dev: { type: 'boolean', default: false },
        policy: { type: 'string' },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  if (parsed.values.help || serverArgs.length === 0) {
    console.log(HELP);
    if (serverArgs.length === 0 && !parsed.values.help) {
      console.error('\nError: server command required after --');
    }
    process.exit(parsed.values.help ? 0 : 1);
  }

  const port = parseInt(parsed.values.port as string, 10);
  const devMode = parsed.values.dev as boolean;
  const policyPath = parsed.values.policy as string | undefined;

  // Load policy if provided
  let toolPolicy: Record<string, { requireBitmask: bigint }> = {};
  if (policyPath) {
    try {
      const fs = await import('fs');
      const { parse } = await import('yaml');
      const raw = fs.readFileSync(policyPath, 'utf-8');
      const config = parse(raw);
      if (config?.tools) {
        for (const [name, pol] of Object.entries(config.tools as Record<string, any>)) {
          if (pol?.requireBitmask !== undefined) {
            toolPolicy[name] = { requireBitmask: BigInt(pol.requireBitmask) };
          }
        }
      }
    } catch (err) {
      console.error(`Error loading policy ${policyPath}: ${(err as Error).message}`);
      process.exit(1);
    }
  }

  // Lazy-import verification from @bolyra/mcp
  const { verifyBundle, checkToolPolicy, MemoryNonceStore } = await import('@bolyra/mcp');
  const nonceStore = new MemoryNonceStore();

  const mcpConfig: any = {
    devMode,
    network: 'base-sepolia',
    nonceStore,
    toolPolicy,
    maxProofAge: 300,
  };

  // Spawn the child MCP server
  const serverCmd = serverArgs[0];
  const serverCmdArgs = serverArgs.slice(1);
  const child: ChildProcess = spawn(serverCmd, serverCmdArgs, {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  child.on('error', (err) => {
    console.error(`Failed to start server: ${err.message}`);
    process.exit(1);
  });

  // Track pending requests (id -> response callback)
  const pending = new Map<string | number, (body: any) => void>();
  let nextInternalId = 1;

  // Read responses from child
  const childReader = readline.createInterface({ input: child.stdout! });
  childReader.on('line', (line: string) => {
    try {
      const msg = JSON.parse(line);
      const resolver = pending.get(msg.id);
      if (resolver) {
        pending.delete(msg.id);
        resolver(msg);
      }
    } catch { /* ignore */ }
  });

  // Send request to child and wait for response
  function sendToChild(msg: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = msg.id ?? nextInternalId++;
      const toSend = { ...msg, id };
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error('Child server timeout'));
      }, 30000);
      pending.set(id, (resp) => {
        clearTimeout(timeout);
        resolve(resp);
      });
      child.stdin!.write(JSON.stringify(toSend) + '\n');
    });
  }

  // HTTP server
  const server = http.createServer(async (req, res) => {
    // Health check
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
      return;
    }

    // Only accept POST
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    // Read body
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', async () => {
      let msg: any;
      try {
        msg = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
        return;
      }

      const method = msg?.method;

      // Auth-exempt methods
      if (method !== 'tools/call') {
        try {
          const childResp = await sendToChild(msg);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(childResp));
        } catch (err) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: 'Server error' } }));
        }
        return;
      }

      // Extract proof from Authorization header or _meta.bolyra
      let bundle: any;
      const authHeader = req.headers['authorization'];
      if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bolyra ')) {
        try {
          bundle = JSON.parse(Buffer.from(authHeader.slice(7), 'base64').toString());
        } catch { /* fall through to _meta */ }
      }
      if (!bundle) {
        bundle = msg?.params?._meta?.bolyra;
      }

      if (!bundle) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: 'Bolyra auth required: missing proof bundle' } }));
        process.stderr.write(JSON.stringify({ decision: 'deny', toolName: msg?.params?.name, reason: 'missing proof', timestamp: new Date().toISOString() }) + '\n');
        return;
      }

      // Verify
      const authCtx = await verifyBundle(bundle, mcpConfig);
      if (!authCtx.verified) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: `Bolyra auth failed: ${authCtx.reason}` } }));
        process.stderr.write(JSON.stringify({ decision: 'deny', toolName: msg?.params?.name, reason: authCtx.reason, timestamp: new Date().toISOString() }) + '\n');
        return;
      }

      // Check tool policy
      const toolName = msg?.params?.name ?? '';
      const decision = checkToolPolicy(toolName, authCtx, mcpConfig);
      if (!decision.allowed) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32001, message: `Bolyra policy denied: ${decision.reason}` } }));
        process.stderr.write(JSON.stringify({ decision: 'deny', toolName, reason: decision.reason, timestamp: new Date().toISOString() }) + '\n');
        return;
      }

      // Authorized — forward to child
      try {
        const childResp = await sendToChild(msg);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(childResp));
        process.stderr.write(JSON.stringify({ decision: 'allow', toolName, did: authCtx.did, score: authCtx.score, timestamp: new Date().toISOString() }) + '\n');
      } catch (err) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: 'Server error' } }));
      }
    });
  });

  server.listen(port, () => {
    const policyCount = Object.keys(toolPolicy).length;
    console.log(`@bolyra/cli — run`);
    console.log(`  MCP endpoint: http://localhost:${port}`);
    console.log(`  Server:       ${serverArgs.join(' ')}`);
    console.log(`  Shield:       enabled (${devMode ? 'dev' : 'production'} mode)`);
    console.log(`  Transport:    stdio → http`);
    console.log(`  Policies:     ${policyCount > 0 ? `${policyCount} tools` : 'none (all verified calls pass)'}`);
    console.log(`  Receipts:     stderr`);
    console.log(`  Health:       http://localhost:${port}/healthz`);
    console.log('');
  });

  // Cleanup
  child.on('exit', (code) => {
    server.close();
    process.exit(code ?? 0);
  });

  process.on('SIGTERM', () => {
    child.kill('SIGTERM');
    server.close();
  });

  process.on('SIGINT', () => {
    child.kill('SIGTERM');
    server.close();
  });
}
