import { spawn, ChildProcess } from 'child_process';
import * as readline from 'readline';
import { verifyBundle, checkToolPolicy, MemoryNonceStore } from '@bolyra/mcp';
import type { BolyraProofBundle, BolyraMcpConfig, ToolPolicyMap } from '@bolyra/mcp';
import type { ShieldConfig } from './config';

export interface ShieldInstance {
  child: ChildProcess;
  stop: () => void;
}

export function createShield(config: ShieldConfig): ShieldInstance {
  const nonceStore = new MemoryNonceStore();
  const toolPolicy: ToolPolicyMap = {};
  for (const [name, policy] of Object.entries(config.tools)) {
    if (policy.requireBitmask !== undefined) {
      toolPolicy[name] = {
        requireBitmask: BigInt(policy.requireBitmask),
        minScore: policy.minScore,
        maxChainDepth: policy.maxChainDepth,
      };
    }
  }

  const mcpConfig: BolyraMcpConfig = {
    devMode: config.devMode,
    network: config.network,
    nonceStore,
    toolPolicy,
    maxProofAge: config.nonce.maxProofAge,
  };

  // Spawn child MCP server
  const parts = config.server.split(/\s+/);
  const child = spawn(parts[0], parts.slice(1), {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  const agentReader = readline.createInterface({ input: process.stdin });
  const serverReader = readline.createInterface({ input: child.stdout! });

  // Forward server responses to agent
  serverReader.on('line', (line: string) => {
    process.stdout.write(line + '\n');
  });

  // Intercept agent requests
  agentReader.on('line', async (line: string) => {
    let msg: any;
    try {
      msg = JSON.parse(line);
    } catch {
      child.stdin!.write(line + '\n');
      return;
    }

    const method = msg?.method;

    // Auth-exempt: forward directly
    if (method !== 'tools/call') {
      child.stdin!.write(line + '\n');
      return;
    }

    // Extract proof
    const bundle: BolyraProofBundle | undefined = msg?.params?._meta?.bolyra;

    if (!bundle) {
      const err = jsonRpcError(msg.id, -32000, 'Bolyra auth required: missing proof bundle in params._meta.bolyra');
      process.stdout.write(JSON.stringify(err) + '\n');
      emitReceipt(config, { decision: 'deny', toolName: msg?.params?.name, reason: 'missing proof', timestamp: new Date().toISOString() });
      return;
    }

    // Verify
    const authCtx = await verifyBundle(bundle, mcpConfig);
    if (!authCtx.verified) {
      const err = jsonRpcError(msg.id, -32000, `Bolyra auth failed: ${authCtx.reason ?? 'unknown'}`);
      process.stdout.write(JSON.stringify(err) + '\n');
      emitReceipt(config, { decision: 'deny', toolName: msg?.params?.name, reason: authCtx.reason, timestamp: new Date().toISOString() });
      return;
    }

    // Check tool policy
    const toolName = msg?.params?.name ?? '';
    const decision = checkToolPolicy(toolName, authCtx, mcpConfig);
    if (!decision.allowed) {
      const err = jsonRpcError(msg.id, -32001, `Bolyra policy denied: ${decision.reason}`);
      process.stdout.write(JSON.stringify(err) + '\n');
      emitReceipt(config, { decision: 'deny', toolName, reason: decision.reason, timestamp: new Date().toISOString() });
      return;
    }

    // Authorized — forward
    child.stdin!.write(line + '\n');
    emitReceipt(config, {
      decision: 'allow',
      toolName,
      did: authCtx.did,
      score: authCtx.score,
      timestamp: new Date().toISOString(),
    });
  });

  child.on('exit', (code: number | null) => {
    process.exit(code ?? 0);
  });

  const stop = () => {
    child.kill('SIGTERM');
    agentReader.close();
    serverReader.close();
  };

  return { child, stop };
}

function jsonRpcError(id: any, code: number, message: string) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function emitReceipt(config: ShieldConfig, receipt: Record<string, any>) {
  if (!config.receipts.enabled) return;
  process.stderr.write(JSON.stringify(receipt) + '\n');
}
