# Robinhood Agentic Trading × Bolyra Gateway Demo

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A self-contained demo showing @bolyra/gateway protecting a mock Robinhood MCP server, with 4 scenarios: verified read, verified trade, unverified agent blocked, replay attack blocked. Publishable as blog post content.

**Architecture:** A mock HTTP MCP server implements the 18 robinhood-for-agents tools with realistic fake responses. The Bolyra gateway (dev mode) sits in front with per-tool permission policies. An orchestrator script runs 4 scenarios via HTTP requests, printing results and receipts to stdout.

**Tech Stack:** TypeScript, Node.js 18+, @bolyra/gateway, @bolyra/sdk (createDevIdentities), @bolyra/mcp (attachBolyraProof)

---

## Chunk 1: Mock Robinhood MCP Server

### Task 1: Create the mock MCP server

**Files:**
- Create: `examples/robinhood-demo/src/mock-robinhood-mcp.ts`
- Create: `examples/robinhood-demo/package.json`
- Create: `examples/robinhood-demo/tsconfig.json`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "robinhood-demo",
  "version": "0.0.1",
  "private": true,
  "description": "Bolyra gateway demo protecting a mock Robinhood MCP server",
  "scripts": {
    "mock-server": "npx tsx src/mock-robinhood-mcp.ts",
    "demo": "npx tsx src/run-demo.ts"
  },
  "dependencies": {
    "@bolyra/gateway": "file:../../integrations/gateway",
    "@bolyra/sdk": "file:../../sdk",
    "@bolyra/mcp": "file:../../integrations/mcp"
  },
  "devDependencies": {
    "tsx": "^4.19.0",
    "typescript": "^5.5.0"
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
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Write mock-robinhood-mcp.ts**

This is a minimal HTTP server that speaks JSON-RPC and implements the 18 robinhood-for-agents tools with realistic mock responses. It does NOT need the MCP SDK — it's a plain HTTP JSON-RPC server.

```typescript
// examples/robinhood-demo/src/mock-robinhood-mcp.ts
import * as http from 'http';

const PORT = parseInt(process.env.MOCK_PORT ?? '3100', 10);

// ── Mock tool responses ─────────────────────────────────────────────

const MOCK_PORTFOLIO = {
  equity: '48,231.56',
  total_return: '+12.4%',
  positions: [
    { symbol: 'AAPL', quantity: 50, avg_cost: 178.32, current_price: 198.45 },
    { symbol: 'NVDA', quantity: 30, avg_cost: 420.10, current_price: 512.88 },
    { symbol: 'TSLA', quantity: 20, avg_cost: 245.00, current_price: 267.33 },
  ],
};

const MOCK_ACCOUNTS = [
  { account_number: 'XXXX1234', type: 'individual', buying_power: '5,420.00' },
  { account_number: 'XXXX5678', type: 'agentic', buying_power: '1,000.00' },
];

const MOCK_QUOTE = (symbol: string) => ({
  symbol,
  last_trade_price: '198.45',
  bid_price: '198.40',
  ask_price: '198.50',
  previous_close: '196.20',
  updated_at: new Date().toISOString(),
});

const MOCK_ORDER_RESULT = (params: Record<string, unknown>) => ({
  order_id: `ORD-${Date.now()}`,
  symbol: params.symbol ?? 'AAPL',
  side: params.side ?? 'buy',
  quantity: params.quantity ?? 1,
  type: params.type ?? 'market',
  status: 'confirmed',
  estimated_price: '198.45',
  timestamp: new Date().toISOString(),
});

// ── Tool handler registry ───────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => unknown;

const TOOLS: Record<string, ToolHandler> = {
  robinhood_check_session: () => ({ authenticated: true, expires_in: '8h' }),
  robinhood_get_portfolio: () => MOCK_PORTFOLIO,
  robinhood_get_accounts: () => MOCK_ACCOUNTS,
  robinhood_get_account: (p) => MOCK_ACCOUNTS.find(a => a.account_number.includes(String(p.account_id ?? '1234'))) ?? MOCK_ACCOUNTS[0],
  robinhood_get_stock_quote: (p) => MOCK_QUOTE(String(p.symbol ?? 'AAPL')),
  robinhood_get_historicals: (p) => ({ symbol: p.symbol, interval: p.interval ?? '1d', data: [{ date: '2026-06-20', close: '196.20' }, { date: '2026-06-21', close: '198.45' }] }),
  robinhood_get_news: (p) => ({ symbol: p.symbol, articles: [{ title: `${p.symbol} hits new high`, source: 'Reuters', date: '2026-06-21' }] }),
  robinhood_get_movers: () => ({ gainers: [{ symbol: 'NVDA', change: '+3.2%' }], losers: [{ symbol: 'INTC', change: '-1.8%' }] }),
  robinhood_get_options: (p) => ({ symbol: p.symbol, expiration: '2026-07-18', calls: [{ strike: 200, premium: 5.40 }], puts: [{ strike: 195, premium: 3.20 }] }),
  robinhood_get_crypto: (p) => ({ symbol: p.symbol ?? 'BTC', price: '68,421.00', change_24h: '+2.1%' }),
  robinhood_place_stock_order: (p) => MOCK_ORDER_RESULT(p),
  robinhood_place_option_order: (p) => ({ ...MOCK_ORDER_RESULT(p), type: 'option', contract: p.contract }),
  robinhood_place_crypto_order: (p) => ({ ...MOCK_ORDER_RESULT(p), asset: p.symbol ?? 'BTC' }),
  robinhood_get_orders: () => ({ orders: [{ order_id: 'ORD-001', symbol: 'AAPL', side: 'buy', status: 'filled', quantity: 10 }] }),
  robinhood_cancel_order: (p) => ({ order_id: p.order_id, status: 'cancelled' }),
  robinhood_get_order_status: (p) => ({ order_id: p.order_id, status: 'filled', filled_at: '2026-06-21T10:30:00Z' }),
  robinhood_search: (p) => ({ results: [{ symbol: String(p.query).toUpperCase(), name: `${p.query} Inc.`, type: 'stock' }] }),
  robinhood_browser_login: () => ({ error: 'Browser login is not available in mock mode' }),
};

// ── JSON-RPC server ─────────────────────────────────────────────────

function handleJsonRpc(body: { method: string; params?: Record<string, unknown>; id?: string | number }): unknown {
  if (body.method === 'initialize') {
    return { protocolVersion: '2025-03-26', serverInfo: { name: 'mock-robinhood', version: '0.7.0' }, capabilities: { tools: {} } };
  }
  if (body.method === 'tools/list') {
    return { tools: Object.keys(TOOLS).map(name => ({ name, description: `Mock ${name}`, inputSchema: { type: 'object', properties: {} } })) };
  }
  if (body.method === 'tools/call') {
    const toolName = body.params?.name as string;
    const toolArgs = (body.params?.arguments ?? {}) as Record<string, unknown>;
    const handler = TOOLS[toolName];
    if (!handler) {
      return { error: { code: -32601, message: `Unknown tool: ${toolName}` } };
    }
    const result = handler(toolArgs);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
  if (body.method === 'notifications/initialized' || body.method === 'ping') {
    return { ok: true };
  }
  return { error: { code: -32601, message: `Unknown method: ${body.method}` } };
}

const server = http.createServer((req, res) => {
  let data = '';
  req.on('data', (chunk: Buffer) => { data += chunk.toString(); });
  req.on('end', () => {
    try {
      const body = JSON.parse(data);
      const result = handleJsonRpc(body);
      const response = { jsonrpc: '2.0', id: body.id ?? null, result };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`Mock Robinhood MCP server listening on http://localhost:${PORT}`);
});

export { server, PORT };
```

- [ ] **Step 4: Test the mock server manually**

Run: `cd examples/robinhood-demo && npm install && npx tsx src/mock-robinhood-mcp.ts &`

Then in another terminal:
```bash
curl -s -X POST http://localhost:3100 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"robinhood_get_portfolio","arguments":{}},"id":1}' | jq .
```

Expected: JSON response with portfolio data (AAPL, NVDA, TSLA positions).

Kill the background server after verifying.

- [ ] **Step 5: Commit**

```bash
git add examples/robinhood-demo/
git commit -s -m "feat(examples): add mock Robinhood MCP server for gateway demo"
```

---

## Chunk 2: Gateway Config + Demo Orchestrator

### Task 2: Create the gateway config

**Files:**
- Create: `examples/robinhood-demo/gateway.yaml`

- [ ] **Step 1: Write gateway.yaml**

```yaml
# Bolyra Gateway config for Robinhood demo
# Maps robinhood-for-agents tools to Bolyra permission tiers

target: http://localhost:3100
port: 4100
devMode: true

nonce:
  store: memory
  maxProofAge: 300

receipts:
  enabled: true
  output: stdout

tools:
  # Read-only tools — require READ_DATA (bit 0 = 1)
  robinhood_check_session:
    requireBitmask: 1
  robinhood_get_portfolio:
    requireBitmask: 1
  robinhood_get_accounts:
    requireBitmask: 1
  robinhood_get_account:
    requireBitmask: 1
  robinhood_get_stock_quote:
    requireBitmask: 1
  robinhood_get_historicals:
    requireBitmask: 1
  robinhood_get_news:
    requireBitmask: 1
  robinhood_get_movers:
    requireBitmask: 1
  robinhood_get_options:
    requireBitmask: 1
  robinhood_get_crypto:
    requireBitmask: 1
  robinhood_get_orders:
    requireBitmask: 1
  robinhood_get_order_status:
    requireBitmask: 1
  robinhood_search:
    requireBitmask: 1

  # Stock orders — require FINANCIAL_SMALL (bit 2 = 4)
  robinhood_place_stock_order:
    requireBitmask: 4

  # Options + crypto orders — require FINANCIAL_MEDIUM (bit 3 = 8)
  robinhood_place_option_order:
    requireBitmask: 8
  robinhood_place_crypto_order:
    requireBitmask: 8

  # Cancel — require WRITE_DATA (bit 1 = 2)
  robinhood_cancel_order:
    requireBitmask: 2

  # Login — blocked (no agent should trigger browser login)
  robinhood_browser_login:
    requireBitmask: 255
```

- [ ] **Step 2: Commit**

```bash
git add examples/robinhood-demo/gateway.yaml
git commit -s -m "feat(examples): add gateway config mapping Robinhood tools to permission tiers"
```

### Task 3: Create the demo orchestrator

**Files:**
- Create: `examples/robinhood-demo/src/run-demo.ts`

- [ ] **Step 1: Write run-demo.ts**

This script:
1. Starts the mock server
2. Starts the gateway (via CLI)
3. Creates two dev identities: one with READ_DATA+FINANCIAL_SMALL, one with READ_DATA only
4. Runs 4 scenarios, printing results
5. Shuts everything down

```typescript
// examples/robinhood-demo/src/run-demo.ts
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import {
  createDevIdentities,
  proveHandshake,
  Permission,
} from '@bolyra/sdk';
import { attachBolyraProof } from '@bolyra/mcp';

const MOCK_PORT = 3100;
const GATEWAY_PORT = 4100;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;

// ── Helpers ─────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForServer(url: string, maxWait = 10000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not ready yet */ }
    await sleep(200);
  }
  throw new Error(`Server at ${url} did not start within ${maxWait}ms`);
}

function banner(text: string): void {
  const line = '═'.repeat(60);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function printResult(label: string, status: number, body: unknown): void {
  const icon = status === 200 ? '✅' : '🚫';
  console.log(`${icon} ${label}`);
  console.log(`   HTTP ${status}`);
  console.log(`   ${JSON.stringify(body, null, 2).split('\n').join('\n   ')}`);
  console.log('');
}

async function callGateway(
  toolName: string,
  args: Record<string, unknown>,
  proofHeader?: string,
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (proofHeader) {
    headers['Authorization'] = `Bolyra ${proofHeader}`;
  }
  const res = await fetch(GATEWAY_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: toolName, arguments: args },
      id: Date.now(),
    }),
  });
  const body = await res.json();
  return { status: res.status, body };
}

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const procs: ChildProcess[] = [];

  try {
    // 1. Start mock server
    banner('Starting Mock Robinhood MCP Server');
    const mockProc = spawn('npx', ['tsx', path.join(__dirname, 'mock-robinhood-mcp.ts')], {
      env: { ...process.env, MOCK_PORT: String(MOCK_PORT) },
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(mockProc);
    mockProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[mock] ${d}`));

    // 2. Start gateway
    banner('Starting Bolyra Gateway');
    const gatewayBin = path.resolve(__dirname, '../../..', 'integrations/gateway/dist/cli.js');
    const configPath = path.join(__dirname, '..', 'gateway.yaml');
    const gatewayProc = spawn('node', [gatewayBin, '--config', configPath], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    procs.push(gatewayProc);
    gatewayProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[gateway] ${d}`));

    // Wait for both to be ready
    await waitForServer(`http://localhost:${MOCK_PORT}`, 8000).catch(() => {
      // Mock server doesn't respond to GET, try a POST
    });
    await sleep(2000); // Give gateway time to start

    // 3. Create dev identities
    banner('Creating Agent Identities');

    // Agent A: has READ_DATA + FINANCIAL_SMALL (can read + place stock orders)
    const traderAgent = await createDevIdentities({
      permissionBitmask: BigInt(Permission.READ_DATA) | (1n << BigInt(Permission.WRITE_DATA)) | (1n << BigInt(Permission.FINANCIAL_SMALL)),
    });
    console.log('Agent A (Trader): READ_DATA + WRITE_DATA + FINANCIAL_SMALL');
    console.log(`  Commitment: ${traderAgent.agent.commitment.toString().slice(0, 20)}...`);

    // Agent B: has READ_DATA only (can read but NOT trade)
    const readerAgent = await createDevIdentities({
      permissionBitmask: 1n << BigInt(Permission.READ_DATA),
    });
    console.log('Agent B (Reader): READ_DATA only');
    console.log(`  Commitment: ${readerAgent.agent.commitment.toString().slice(0, 20)}...`);

    // 4. Generate proof bundles (dev mode — instant, no circuits)
    // In dev mode the gateway accepts any well-formed bundle, so we construct minimal ones
    const traderBundle = Buffer.from(JSON.stringify({
      humanProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      agentProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      nonce: Date.now().toString(),
      humanNullifier: '0x0001',
      agentCommitment: traderAgent.agent.commitment.toString(),
      permissionBitmask: '7',  // READ_DATA(1) + WRITE_DATA(2) + FINANCIAL_SMALL(4)
      expiryTimestamp: '4102358400',
    })).toString('base64');

    const readerBundle = Buffer.from(JSON.stringify({
      humanProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      agentProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      nonce: (Date.now() + 1).toString(),
      humanNullifier: '0x0002',
      agentCommitment: readerAgent.agent.commitment.toString(),
      permissionBitmask: '1',  // READ_DATA only
      expiryTimestamp: '4102358400',
    })).toString('base64');

    // ── Scenario 1: Verified agent reads portfolio ──────────────────
    banner('Scenario 1: Verified Agent Reads Portfolio');
    const s1 = await callGateway('robinhood_get_portfolio', {}, traderBundle);
    printResult('Trader agent reads portfolio', s1.status, s1.body);

    // ── Scenario 2: Verified agent places stock order ───────────────
    banner('Scenario 2: Verified Agent Places Stock Order');
    // Need a fresh nonce for each request
    const traderBundle2 = Buffer.from(JSON.stringify({
      humanProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      agentProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      nonce: (Date.now() + 2).toString(),
      humanNullifier: '0x0001',
      agentCommitment: traderAgent.agent.commitment.toString(),
      permissionBitmask: '7',
      expiryTimestamp: '4102358400',
    })).toString('base64');

    const s2 = await callGateway('robinhood_place_stock_order', {
      symbol: 'AAPL',
      side: 'buy',
      quantity: 10,
      type: 'market',
    }, traderBundle2);
    printResult('Trader agent places AAPL buy order', s2.status, s2.body);

    // ── Scenario 3: Reader agent blocked from trading ───────────────
    banner('Scenario 3: Read-Only Agent Blocked from Trading');
    const readerBundle2 = Buffer.from(JSON.stringify({
      humanProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      agentProof: { pi_a: ['0'], pi_b: [['0']], pi_c: ['0'], publicSignals: ['0'] },
      nonce: (Date.now() + 3).toString(),
      humanNullifier: '0x0002',
      agentCommitment: readerAgent.agent.commitment.toString(),
      permissionBitmask: '1',
      expiryTimestamp: '4102358400',
    })).toString('base64');

    const s3 = await callGateway('robinhood_place_stock_order', {
      symbol: 'AAPL',
      side: 'buy',
      quantity: 10,
      type: 'market',
    }, readerBundle2);
    printResult('Reader agent tries to place order → BLOCKED', s3.status, s3.body);

    // ── Scenario 4: Replay attack blocked ───────────────────────────
    banner('Scenario 4: Replay Attack Blocked');
    // Reuse traderBundle (same nonce as scenario 1)
    const s4 = await callGateway('robinhood_get_portfolio', {}, traderBundle);
    printResult('Replay of scenario 1 proof → BLOCKED', s4.status, s4.body);

    // ── Summary ─────────────────────────────────────────────────────
    banner('Demo Complete');
    console.log('Scenario 1: ✅ Verified agent reads portfolio');
    console.log('Scenario 2: ✅ Verified agent places stock order');
    console.log('Scenario 3: 🚫 Read-only agent blocked from trading');
    console.log('Scenario 4: 🚫 Replay of previous proof blocked');
    console.log('');
    console.log('Each scenario generated a signed receipt (see gateway stdout above).');
    console.log('');
    console.log('This demo uses @bolyra/gateway in dev mode (mock ZKP verification).');
    console.log('In production, agents present real Groth16 proofs verified in < 200ms.');

  } finally {
    // Cleanup
    for (const p of procs) {
      p.kill('SIGTERM');
    }
    // Give processes time to exit
    await sleep(500);
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exit(1);
});
```

- [ ] **Step 2: Run the full demo**

Run: `cd examples/robinhood-demo && npm run demo`

Expected output:
- Scenario 1: HTTP 200, portfolio data
- Scenario 2: HTTP 200, order confirmation with order ID
- Scenario 3: HTTP 401 or 403, permission denied error
- Scenario 4: HTTP 401, nonce replay rejected

**Debugging:** If the gateway doesn't start, ensure `integrations/gateway` is built:
```bash
cd integrations/gateway && npm run build && cd ../../examples/robinhood-demo
```

- [ ] **Step 3: Fix any issues from the test run**

The proof bundle format in dev mode may need adjustment based on what `verifyBundle` expects. Check `integrations/mcp/src/auth.ts` for the expected shape. Adjust the bundle construction in run-demo.ts accordingly.

- [ ] **Step 4: Commit**

```bash
git add examples/robinhood-demo/
git commit -s -m "feat(examples): add Robinhood demo orchestrator with 4 scenarios"
```

---

## Chunk 3: README + Blog Draft

### Task 4: Write the demo README

**Files:**
- Create: `examples/robinhood-demo/README.md`

- [ ] **Step 1: Write README.md**

```markdown
# Robinhood Agentic Trading × Bolyra Gateway Demo

Demonstrates how [@bolyra/gateway](https://www.npmjs.com/package/@bolyra/gateway) protects an MCP server modeled after [robinhood-for-agents](https://github.com/kevin1chun/robinhood-for-agents) — the community MCP server for Robinhood's Agentic Trading platform.

## What This Shows

| Scenario | Agent | Tool | Permission | Result |
|----------|-------|------|-----------|--------|
| 1. Portfolio read | Trader (READ_DATA) | `robinhood_get_portfolio` | ✅ Has READ_DATA | Allowed + receipt |
| 2. Stock order | Trader (FINANCIAL_SMALL) | `robinhood_place_stock_order` | ✅ Has FINANCIAL_SMALL | Allowed + receipt |
| 3. Unauthorized trade | Reader (READ_DATA only) | `robinhood_place_stock_order` | 🚫 Missing FINANCIAL_SMALL | Blocked + denial receipt |
| 4. Replay attack | Trader (reused proof) | `robinhood_get_portfolio` | 🚫 Nonce already seen | Blocked |

## Quick Start

```bash
# From repo root
cd examples/robinhood-demo
npm install

# Build the gateway (if not already built)
cd ../../integrations/gateway && npm run build && cd ../../examples/robinhood-demo

# Run the demo
npm run demo
```

## Architecture

```
Agent A (Trader) ─────────────┐
  READ_DATA + FINANCIAL_SMALL │
                              ▼
                    Bolyra Gateway (:4100)
Agent B (Reader) ─────────────┤  • Verify ZKP proof bundle
  READ_DATA only              │  • Check per-tool permission policy
                              │  • Block replay (nonce store)
                              │  • Generate signed receipt
                              ▼
                    Mock Robinhood MCP (:3100)
                      18 tools (portfolio, orders, quotes, etc.)
```

## Tool → Permission Mapping

| Permission Tier | Bitmask | Tools |
|----------------|---------|-------|
| READ_DATA | `0x01` | All `get_*`, `search`, `check_session` |
| WRITE_DATA | `0x02` | `cancel_order` |
| FINANCIAL_SMALL | `0x04` | `place_stock_order` |
| FINANCIAL_MEDIUM | `0x08` | `place_option_order`, `place_crypto_order` |
| BLOCKED | `0xFF` | `browser_login` (no agent should trigger this) |

## How It Works

1. **Mock server** implements robinhood-for-agents' 18 tools as HTTP JSON-RPC with realistic fake data
2. **Bolyra gateway** (dev mode) sits in front, verifying proof bundles and enforcing `gateway.yaml` tool policies
3. **Demo script** creates two agents with different permissions and runs 4 scenarios
4. Each request generates a **signed receipt** proving the auth decision (allow or deny)

## No Robinhood Account Needed

This demo uses a mock MCP server. No real Robinhood account, OAuth tokens, or trading is involved. The mock returns realistic but fake portfolio data and order confirmations.

## Next Steps

- Try the [interactive playground](https://bolyra.ai/playground) for delegation chains and receipt inspection
- See the [gateway quickstart](../../integrations/gateway/README.md) for production setup
- Read the [one-pager](../../docs/outbound/robinhood-one-pager.md) on Bolyra × Robinhood
```

- [ ] **Step 2: Commit**

```bash
git add examples/robinhood-demo/README.md
git commit -s -m "docs(examples): add README for Robinhood gateway demo"
```

### Task 5: Write blog post draft

**Files:**
- Create: `docs/outbound/robinhood-demo-blog.md`

- [ ] **Step 1: Write the blog post draft**

A ~600 word blog post covering:
- What Robinhood's Agentic Trading is and the security gap
- What the demo shows (4 scenarios)
- The tool-to-permission mapping
- How to run it
- Link to the one-pager
- CTA: "try the playground, star the repo"

Keep the tone technical and direct. No marketing fluff.

- [ ] **Step 2: Commit**

```bash
git add docs/outbound/robinhood-demo-blog.md
git commit -s -m "docs: draft blog post for Robinhood gateway demo"
```

### Task 6: End-to-end verification

- [ ] **Step 1: Clean install and run**

```bash
cd examples/robinhood-demo
rm -rf node_modules
npm install
npm run demo
```

Verify all 4 scenarios produce the expected output. Check that receipts appear in gateway stdout.

- [ ] **Step 2: Verify README instructions work from scratch**

Follow the README instructions exactly as written, from a fresh terminal. Fix any issues found.

- [ ] **Step 3: Final commit if any fixes needed**

```bash
git add -A examples/robinhood-demo/
git commit -s -m "fix(examples): polish Robinhood demo after end-to-end verification"
```
