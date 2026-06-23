# @bolyra/shield Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdio MCP proxy that wraps any MCP server, intercepts `tools/call` requests, enforces per-tool permission policy via Bolyra proof verification, and generates audit receipts.

**Architecture:** Shield spawns the target MCP server as a child process (stdin/stdout). Shield itself is a stdio MCP server. On `initialize` and `tools/list`, it forwards transparently. On `tools/call`, it extracts the proof from `params._meta.bolyra`, calls `verifyBundle()` + `checkToolPolicy()` from `@bolyra/mcp`, and either forwards or returns a JSON-RPC error. Receipts are emitted to stderr (not stdout, which is the MCP transport).

**Tech Stack:** TypeScript, Node.js 18+, `@bolyra/mcp` (verifyBundle, checkToolPolicy, MemoryNonceStore), `yaml` (config parsing)

---

## File Structure

```
integrations/shield/
├── package.json
├── tsconfig.json
├── src/
│   ├── cli.ts          — CLI entry point (parse args, load config, start shield)
│   ├── shield.ts       — stdio JSON-RPC proxy with auth intercept
│   ├── config.ts       — load shield.yaml (reuse gateway pattern)
│   └── index.ts        — public exports
└── test/
    └── shield.test.ts  — spawn mock server, wrap with shield, test 4 scenarios
```

---

### Task 1: Scaffold package

**Files:**
- Create: `integrations/shield/package.json`
- Create: `integrations/shield/tsconfig.json`
- Create: `integrations/shield/src/index.ts`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "@bolyra/shield",
  "version": "0.1.0",
  "mcpName": "io.github.bolyra/shield",
  "description": "Stdio MCP auth proxy — wrap any MCP server with per-tool permission enforcement",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "bin": {
    "bolyra-shield": "dist/cli.js"
  },
  "scripts": {
    "build": "tsc",
    "test": "jest --passWithNoTests",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@bolyra/mcp": "file:../mcp",
    "yaml": "^2.4.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.0",
    "typescript": "^5.5.0"
  },
  "files": ["dist", "src", "README.md", "LICENSE", "NOTICE"],
  "license": "Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/bolyra/bolyra",
    "directory": "integrations/shield"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "strict": true,
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create src/index.ts**

```typescript
export { createShield } from './shield';
export type { ShieldConfig } from './config';
```

- [ ] **Step 4: Install and verify**

```bash
cd integrations/shield && npm install && npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
git add integrations/shield/
git commit -s -m "feat(shield): scaffold @bolyra/shield package"
```

---

### Task 2: Config loader

**Files:**
- Create: `integrations/shield/src/config.ts`

- [ ] **Step 1: Write config.ts**

Reuses the same YAML format as gateway.yaml. Loads `shield.yaml`, substitutes env vars, validates.

```typescript
import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';

export interface ShieldToolPolicy {
  requireBitmask?: number;
  minScore?: number;
  maxChainDepth?: number;
}

export interface ShieldConfig {
  server: string;           // command to spawn the MCP server
  devMode: boolean;
  network: string;
  nonce: { store: 'memory'; maxProofAge: number };
  receipts: { enabled: boolean; output: 'stderr' | 'file'; dir?: string };
  tools: Record<string, ShieldToolPolicy>;
}

const DEFAULTS: ShieldConfig = {
  server: '',
  devMode: false,
  network: 'base-sepolia',
  nonce: { store: 'memory', maxProofAge: 300 },
  receipts: { enabled: true, output: 'stderr' },
  tools: {},
};

function substituteEnvVars(obj: any): any {
  if (typeof obj === 'string') {
    return obj.replace(/\$\{([^}]+)\}/g, (_m, v) => process.env[v] ?? `\${${v}}`);
  }
  if (Array.isArray(obj)) return obj.map(substituteEnvVars);
  if (obj !== null && typeof obj === 'object') {
    const r: any = {};
    for (const [k, v] of Object.entries(obj)) r[k] = substituteEnvVars(v);
    return r;
  }
  return obj;
}

export function loadShieldConfig(configPath: string, cliServer?: string): ShieldConfig {
  let fileConfig: Record<string, any> = {};
  const resolved = path.resolve(configPath);
  if (fs.existsSync(resolved)) {
    const raw = fs.readFileSync(resolved, 'utf-8');
    fileConfig = substituteEnvVars(parseYaml(raw) ?? {});
  }

  const config: ShieldConfig = {
    ...DEFAULTS,
    ...fileConfig,
    nonce: { ...DEFAULTS.nonce, ...(fileConfig.nonce ?? {}) },
    receipts: { ...DEFAULTS.receipts, ...(fileConfig.receipts ?? {}) },
    tools: fileConfig.tools ?? {},
  };

  if (cliServer) config.server = cliServer;

  if (!config.server) {
    throw new Error('@bolyra/shield: --server is required (command to spawn the MCP server)');
  }

  return config;
}
```

- [ ] **Step 2: Commit**

```bash
git add integrations/shield/src/config.ts
git commit -s -m "feat(shield): add YAML config loader"
```

---

### Task 3: Shield core (stdio proxy with auth intercept)

**Files:**
- Create: `integrations/shield/src/shield.ts`

- [ ] **Step 1: Write shield.ts**

This is the core: spawn child process, proxy stdin/stdout JSON-RPC, intercept tools/call.

```typescript
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
  // Build MCP config for verifyBundle/checkToolPolicy
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

  // Read lines from stdin (agent → shield)
  const agentReader = readline.createInterface({ input: process.stdin });
  // Read lines from child stdout (server → shield)
  const serverReader = readline.createInterface({ input: child.stdout! });

  // Forward server responses to agent (stdout)
  serverReader.on('line', (line) => {
    process.stdout.write(line + '\n');
  });

  // Intercept agent requests
  agentReader.on('line', async (line) => {
    let msg: any;
    try {
      msg = JSON.parse(line);
    } catch {
      // Not JSON, forward as-is
      child.stdin!.write(line + '\n');
      return;
    }

    const method = msg?.method;

    // Auth-exempt methods: forward directly
    if (method !== 'tools/call') {
      child.stdin!.write(line + '\n');
      return;
    }

    // Extract proof bundle from _meta.bolyra
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

    // Authorized — forward to child server
    child.stdin!.write(line + '\n');
    emitReceipt(config, {
      decision: 'allow',
      toolName,
      did: authCtx.did,
      score: authCtx.score,
      timestamp: new Date().toISOString(),
    });
  });

  // Handle child exit
  child.on('exit', (code) => {
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
  // Receipts go to stderr (stdout is the MCP transport)
  process.stderr.write(JSON.stringify(receipt) + '\n');
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd integrations/shield && npx tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add integrations/shield/src/shield.ts
git commit -s -m "feat(shield): add stdio proxy core with auth intercept"
```

---

### Task 4: CLI entry point

**Files:**
- Create: `integrations/shield/src/cli.ts`

- [ ] **Step 1: Write cli.ts**

```typescript
#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { loadShieldConfig } from './config';
import { createShield } from './shield';

const VERSION = (require('../package.json') as { version: string }).version;

const HELP = `
@bolyra/shield v${VERSION}
Stdio MCP auth proxy — wrap any MCP server with per-tool permission enforcement.

Usage:
  bolyra-shield --server "<command>" [options]
  npx @bolyra/shield --server "<command>" [options]

Options:
  --server <cmd>     Command to spawn the MCP server (required)
  --config <path>    Path to shield config file (default: ./shield.yaml)
  --dev              Enable dev mode (mock verification)
  --help             Show this help
  --version          Show version

Examples:
  # Wrap the filesystem MCP server
  bolyra-shield --server "npx @modelcontextprotocol/server-filesystem /tmp" --dev

  # With config file
  bolyra-shield --server "node my-server.js" --config ./shield.yaml
`.trim();

function main(argv: string[] = process.argv.slice(2)): void {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        server: { type: 'string' },
        config: { type: 'string', default: './shield.yaml' },
        dev: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
        version: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  const { values } = parsed;

  if (values.help) { console.log(HELP); process.exit(0); }
  if (values.version) { console.log(VERSION); process.exit(0); }

  const config = loadShieldConfig(
    values.config as string,
    values.server as string | undefined,
  );

  if (values.dev) config.devMode = true;

  // Banner to stderr (stdout is MCP transport)
  process.stderr.write(`@bolyra/shield v${VERSION}\n`);
  process.stderr.write(`  Server:  ${config.server}\n`);
  process.stderr.write(`  Mode:    ${config.devMode ? 'dev' : 'production'}\n`);
  process.stderr.write(`  Tools:   ${Object.keys(config.tools).length} policies\n`);
  process.stderr.write(`  Receipts: stderr\n\n`);

  createShield(config);
}

main();
```

- [ ] **Step 2: Add shebang line to tsconfig**

In tsconfig.json, ensure `"declaration": true` is set (already done).

- [ ] **Step 3: Build and verify**

```bash
cd integrations/shield && npm run build
node dist/cli.js --help
```

Expected: help text prints to stdout.

- [ ] **Step 4: Commit**

```bash
git add integrations/shield/src/cli.ts
git commit -s -m "feat(shield): add CLI entry point"
```

---

### Task 5: Integration test (4 scenarios)

**Files:**
- Create: `integrations/shield/test/shield.test.ts`
- Create: `integrations/shield/test/mock-server.ts`

- [ ] **Step 1: Create a mock stdio MCP server for testing**

`test/mock-server.ts` — a minimal stdio MCP server that reads JSON-RPC from stdin and responds on stdout.

```typescript
// integrations/shield/test/mock-server.ts
// Run standalone: node -e "require('./mock-server')"
import * as readline from 'readline';

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', (line) => {
  let msg: any;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { protocolVersion: '2025-03-26', serverInfo: { name: 'mock', version: '0.1.0' }, capabilities: { tools: {} } },
    }) + '\n');
  } else if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { tools: [
        { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object' } },
        { name: 'write_file', description: 'Write a file', inputSchema: { type: 'object' } },
      ] },
    }) + '\n');
  } else if (msg.method === 'tools/call') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { content: [{ type: 'text', text: `executed ${msg.params?.name}` }] },
    }) + '\n');
  }
});
```

- [ ] **Step 2: Write shield.test.ts**

Test the 4 scenarios by spawning shield wrapping the mock server.

```typescript
// integrations/shield/test/shield.test.ts
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as readline from 'readline';

const SHIELD_BIN = path.resolve(__dirname, '../dist/cli.js');
const MOCK_SERVER = `npx tsx ${path.resolve(__dirname, 'mock-server.ts')}`;

function makeDevBundle(permissionBitmask: number, seed: number): any {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const entropy = BigInt(seed);
  const nonce = ((nowSec << 64n) | entropy).toString();
  return {
    v: 1, _dev: true,
    humanProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0','0'] },
    agentProof: { pi_a: ['0','0','1'], pi_b: [['0','0'],['0','0'],['1','0']], pi_c: ['0','0','1'], publicSignals: ['0','0','0', String(permissionBitmask)] },
    nonce,
    credentialCommitment: String(seed),
  };
}

function sendAndReceive(child: ChildProcess, msg: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input: child.stdout! });
    const timeout = setTimeout(() => reject(new Error('timeout')), 5000);
    rl.once('line', (line) => {
      clearTimeout(timeout);
      rl.close();
      resolve(JSON.parse(line));
    });
    child.stdin!.write(JSON.stringify(msg) + '\n');
  });
}

describe('@bolyra/shield', () => {
  let shield: ChildProcess;

  beforeAll((done) => {
    shield = spawn('node', [SHIELD_BIN, '--server', MOCK_SERVER, '--dev'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
    });
    // Wait for banner on stderr
    shield.stderr!.once('data', () => setTimeout(done, 500));
  });

  afterAll(() => { shield.kill('SIGTERM'); });

  test('Scenario 1: verified read_file allowed', async () => {
    const bundle = makeDevBundle(1, 1001); // READ_DATA
    const res = await sendAndReceive(shield, {
      jsonrpc: '2.0', method: 'tools/call', id: 1,
      params: { name: 'read_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.error).toBeUndefined();
  });

  test('Scenario 2: verified write_file with WRITE_DATA allowed', async () => {
    const bundle = makeDevBundle(3, 1002); // READ+WRITE
    const res = await sendAndReceive(shield, {
      jsonrpc: '2.0', method: 'tools/call', id: 2,
      params: { name: 'write_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.result).toBeDefined();
    expect(res.error).toBeUndefined();
  });

  test('Scenario 3: read-only agent blocked from write_file', async () => {
    const bundle = makeDevBundle(1, 1003); // READ_DATA only
    const res = await sendAndReceive(shield, {
      jsonrpc: '2.0', method: 'tools/call', id: 3,
      params: { name: 'write_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.error).toBeDefined();
    expect(res.error.message).toContain('policy denied');
  });

  test('Scenario 4: replay blocked', async () => {
    const bundle = makeDevBundle(1, 1001); // same seed as scenario 1 = same nonce
    const res = await sendAndReceive(shield, {
      jsonrpc: '2.0', method: 'tools/call', id: 4,
      params: { name: 'read_file', arguments: {}, _meta: { bolyra: bundle } },
    });
    expect(res.error).toBeDefined();
    expect(res.error.message).toContain('replay');
  });
});
```

- [ ] **Step 3: Add jest config to package.json**

Add to package.json:
```json
"jest": {
  "preset": "ts-jest",
  "testEnvironment": "node",
  "testTimeout": 15000
}
```

- [ ] **Step 4: Build and run tests**

```bash
cd integrations/shield && npm run build && npm test
```

Expected: 4 tests pass.

- [ ] **Step 5: Fix any issues and re-run**

- [ ] **Step 6: Commit**

```bash
git add integrations/shield/test/
git commit -s -m "test(shield): add 4-scenario integration test"
```

---

### Task 6: README + shield.yaml example

**Files:**
- Create: `integrations/shield/README.md`
- Create: `integrations/shield/shield.yaml.example`

- [ ] **Step 1: Write README.md**

Brief README: what it does, quick start, config reference, link to gateway for HTTP.

- [ ] **Step 2: Write shield.yaml.example**

```yaml
# shield.yaml — Bolyra MCP Shield config
server: "npx @modelcontextprotocol/server-filesystem /tmp"
devMode: true

nonce:
  store: memory
  maxProofAge: 300

receipts:
  enabled: true
  output: stderr

tools:
  read_file:
    requireBitmask: 1    # READ_DATA
  write_file:
    requireBitmask: 2    # WRITE_DATA
  delete_file:
    requireBitmask: 2    # WRITE_DATA
```

- [ ] **Step 3: Commit**

```bash
git add integrations/shield/README.md integrations/shield/shield.yaml.example
git commit -s -m "docs(shield): add README and example config"
```
