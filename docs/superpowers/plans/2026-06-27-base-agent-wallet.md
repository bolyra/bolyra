# Base Agent Wallet Integration — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a runnable demo (`npx @bolyra/base-agent-wallet`) + playground tab showing human-gated spending on Base — agents prove ZKP-enforced authorization before paying, without revealing who authorized them.

**Architecture:** New example package `examples/base-agent-wallet/` extends the existing `BolyraAgentWallet` pattern with Bolyra SDK integration (real `createHumanIdentity` + `createAgentCredential` + `delegate` calls). Mock paid API reused. A new playground tab on `landing/playground.html` visualizes the same flow in-browser.

**Tech Stack:** TypeScript, @bolyra/sdk, tsx, Node http server, vanilla HTML/CSS/JS (playground)

---

## File Structure

```
examples/base-agent-wallet/
  package.json              # publishable as @bolyra/base-agent-wallet
  tsconfig.json
  src/
    index.ts                # CLI entry point (npx bin)
    base-wallet.ts          # BaseAgentWallet class (extends x402 pattern + SDK integration)
    delegation.ts           # Human delegation flow (createHumanIdentity -> delegate -> policy)
    paid-api.ts             # Mock x402 API server (copy from x402-agent-wallet, add Base branding)
    demo-runner.ts          # 6-scenario orchestrator with narrative output
  test/
    base-wallet.test.ts     # Unit tests for policy enforcement
    delegation.test.ts      # Unit tests for delegation flow

landing/
  playground.html           # Add 4th tab: "Base Wallet" (modify existing)
```

---

## Chunk 1: Core Package Setup + BaseAgentWallet

### Task 1: Scaffold the package

**Files:**
- Create: `examples/base-agent-wallet/package.json`
- Create: `examples/base-agent-wallet/tsconfig.json`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "@bolyra/base-agent-wallet",
  "version": "0.1.0",
  "description": "Human-gated spending for AI agents on Base. ZKP-enforced wallet delegation.",
  "license": "Apache-2.0",
  "bin": {
    "base-agent-wallet": "./src/index.ts"
  },
  "scripts": {
    "demo": "npx tsx src/index.ts",
    "test": "npx tsx --test test/*.test.ts"
  },
  "dependencies": {
    "@bolyra/sdk": "file:../../sdk"
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
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true
  },
  "include": ["src/**/*", "test/**/*"]
}
```

- [ ] **Step 3: Install dependencies**

Run: `cd examples/base-agent-wallet && npm install`

- [ ] **Step 4: Commit**

```bash
cd ~/Projects/bolyra
git add examples/base-agent-wallet/package.json examples/base-agent-wallet/tsconfig.json
git commit -s -m "feat(base-agent-wallet): scaffold package"
```

---

### Task 2: Write the delegation module

This module creates a human identity, an agent credential, and produces a delegation proof. It wraps the SDK calls into a simple `setupDelegation()` function that the demo calls.

**Files:**
- Create: `examples/base-agent-wallet/test/delegation.test.ts`
- Create: `examples/base-agent-wallet/src/delegation.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// test/delegation.test.ts
import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { setupDelegation } from '../src/delegation.js';

describe('setupDelegation', () => {
  it('returns human identity, agent credential, and wallet policy', async () => {
    const result = await setupDelegation({
      maxPerRequest: 200,
      dailyCap: 500,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
      permissions: ['READ_DATA', 'FINANCIAL_SMALL'],
      expiryMinutes: 60,
    });

    assert.ok(result.humanIdentity, 'should have humanIdentity');
    assert.ok(result.humanIdentity.commitment, 'humanIdentity should have commitment');
    assert.ok(result.agentCredential, 'should have agentCredential');
    assert.ok(result.agentCredential.commitment, 'agentCredential should have commitment');
    assert.ok(result.walletPolicy, 'should have walletPolicy');
    assert.equal(result.walletPolicy.maxPerRequest, 200);
    assert.equal(result.walletPolicy.dailyCap, 500);
    assert.ok(result.walletPolicy.agentDid.startsWith('did:bolyra:base-sepolia:'));
    assert.ok(result.agentCredential.permissionBitmask > 0n, 'should have permissions set');
  });

  it('enforces scope narrowing — cannot exceed requested permissions', async () => {
    const result = await setupDelegation({
      maxPerRequest: 100,
      dailyCap: 100,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
      permissions: ['READ_DATA'],
      expiryMinutes: 30,
    });

    // READ_DATA is bit 0 = bitmask 1
    assert.equal(result.agentCredential.permissionBitmask, 1n);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd examples/base-agent-wallet && npx tsx --test test/delegation.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the delegation module**

```typescript
// src/delegation.ts
import {
  createHumanIdentity,
  createAgentCredential,
  permissionsToBitmask,
  type HumanIdentity,
  type AgentCredential,
  Permission,
} from '@bolyra/sdk';

export interface DelegationConfig {
  maxPerRequest: number;      // cents
  dailyCap: number;           // cents
  allowedAssets: string[];
  allowedNetworks: string[];
  permissions: string[];      // e.g. ['READ_DATA', 'FINANCIAL_SMALL']
  expiryMinutes: number;
}

export interface WalletPolicy {
  maxPerRequest: number;
  dailyCap: number;
  allowedAssets: string[];
  allowedNetworks: string[];
  agentDid: string;
  expiresAt: string;
}

export interface DelegationResult {
  humanIdentity: HumanIdentity;
  agentCredential: AgentCredential;
  walletPolicy: WalletPolicy;
}

export async function setupDelegation(config: DelegationConfig): Promise<DelegationResult> {
  // 1. Human creates identity (simulates the wallet owner)
  const secret = BigInt('0x' + Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 16).toString(16)).join(''));
  const humanIdentity = await createHumanIdentity(secret);

  // 2. Create agent credential with requested permissions
  const permBitmask = permissionsToBitmask(
    config.permissions.map(p => Permission[p as keyof typeof Permission])
  );
  const expiryTimestamp = BigInt(
    Math.floor(Date.now() / 1000) + config.expiryMinutes * 60
  );

  const agentCredential = await createAgentCredential(
    BigInt('0xAGENT_MODEL_GPT4'),     // modelHash — identifies the agent model
    humanIdentity.secret,               // operator signs with human's key
    permBitmask,
    expiryTimestamp,
  );

  // 3. Derive agent DID from credential commitment
  const agentDid = `did:bolyra:base-sepolia:${agentCredential.commitment.toString(16).slice(0, 40)}`;

  // 4. Build wallet policy
  const walletPolicy: WalletPolicy = {
    maxPerRequest: config.maxPerRequest,
    dailyCap: config.dailyCap,
    allowedAssets: config.allowedAssets,
    allowedNetworks: config.allowedNetworks,
    agentDid,
    expiresAt: new Date(Number(expiryTimestamp) * 1000).toISOString(),
  };

  return { humanIdentity, agentCredential, walletPolicy };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd examples/base-agent-wallet && npx tsx --test test/delegation.test.ts`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add examples/base-agent-wallet/src/delegation.ts examples/base-agent-wallet/test/delegation.test.ts
git commit -s -m "feat(base-agent-wallet): delegation module — human identity + agent credential"
```

---

### Task 3: Write the BaseAgentWallet class

Extends the x402 agent wallet pattern with Bolyra proof envelope integration. The key difference from the existing `BolyraAgentWallet`: this one carries the `agentCredential` and can generate a Bolyra proof envelope alongside the x402 payment header.

**Files:**
- Create: `examples/base-agent-wallet/test/base-wallet.test.ts`
- Create: `examples/base-agent-wallet/src/base-wallet.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
// test/base-wallet.test.ts
import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { BaseAgentWallet } from '../src/base-wallet.js';

describe('BaseAgentWallet', () => {
  const policy = {
    maxPerRequest: 200,
    dailyCap: 500,
    allowedAssets: ['USDC'],
    allowedNetworks: ['base-sepolia'],
    agentDid: 'did:bolyra:base-sepolia:0xtest123',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  };

  it('allows payment within policy limits', () => {
    const wallet = new BaseAgentWallet(policy);
    const result = wallet.evaluatePayment({
      amount: 100, asset: 'USDC', network: 'base-sepolia',
    });
    assert.equal(result.decision, 'allow');
  });

  it('denies payment exceeding per-request cap', () => {
    const wallet = new BaseAgentWallet(policy);
    const result = wallet.evaluatePayment({
      amount: 300, asset: 'USDC', network: 'base-sepolia',
    });
    assert.equal(result.decision, 'deny');
    assert.ok(result.reason?.includes('per-request'));
  });

  it('denies payment exceeding daily cap', () => {
    const wallet = new BaseAgentWallet(policy);
    // Spend 4 x $1.00 = $4.00 of $5.00 cap
    for (let i = 0; i < 4; i++) {
      wallet.evaluatePayment({ amount: 100, asset: 'USDC', network: 'base-sepolia' });
    }
    // This $1.50 would push to $5.50 > $5.00
    const result = wallet.evaluatePayment({
      amount: 150, asset: 'USDC', network: 'base-sepolia',
    });
    assert.equal(result.decision, 'deny');
    assert.ok(result.reason?.includes('daily'));
  });

  it('denies wrong asset', () => {
    const wallet = new BaseAgentWallet(policy);
    const result = wallet.evaluatePayment({
      amount: 50, asset: 'DAI', network: 'base-sepolia',
    });
    assert.equal(result.decision, 'deny');
    assert.ok(result.reason?.includes('asset'));
  });

  it('denies wrong network', () => {
    const wallet = new BaseAgentWallet(policy);
    const result = wallet.evaluatePayment({
      amount: 50, asset: 'USDC', network: 'ethereum',
    });
    assert.equal(result.decision, 'deny');
    assert.ok(result.reason?.includes('network'));
  });

  it('denies expired delegation', () => {
    const expiredPolicy = { ...policy, expiresAt: new Date(Date.now() - 1000).toISOString() };
    const wallet = new BaseAgentWallet(expiredPolicy);
    const result = wallet.evaluatePayment({
      amount: 50, asset: 'USDC', network: 'base-sepolia',
    });
    assert.equal(result.decision, 'deny');
    assert.ok(result.reason?.includes('expired'));
  });

  it('tracks receipts', () => {
    const wallet = new BaseAgentWallet(policy);
    wallet.evaluatePayment({ amount: 100, asset: 'USDC', network: 'base-sepolia' });
    wallet.evaluatePayment({ amount: 300, asset: 'USDC', network: 'base-sepolia' });
    const receipts = wallet.getReceipts();
    assert.equal(receipts.length, 2);
    assert.equal(receipts[0].decision, 'allow');
    assert.equal(receipts[1].decision, 'deny');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd examples/base-agent-wallet && npx tsx --test test/base-wallet.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write BaseAgentWallet**

```typescript
// src/base-wallet.ts
import type { WalletPolicy } from './delegation.js';

export interface PaymentRequest {
  amount: number;     // cents
  asset: string;
  network: string;
}

export interface Receipt {
  id: string;
  decision: 'allow' | 'deny';
  amount: number;
  asset: string;
  network: string;
  reason?: string;
  agentDid: string;
  timestamp: string;
  dailySpent: number;
  dailyRemaining: number;
}

export class BaseAgentWallet {
  private policy: WalletPolicy;
  private dailySpent = 0;
  private receipts: Receipt[] = [];

  constructor(policy: WalletPolicy) {
    this.policy = policy;
  }

  evaluatePayment(req: PaymentRequest): Receipt {
    // Check expiry
    if (new Date() > new Date(this.policy.expiresAt)) {
      return this.emit('deny', req, 'delegation expired');
    }

    // Check asset
    if (!this.policy.allowedAssets.includes(req.asset)) {
      return this.emit('deny', req, `asset ${req.asset} not in allowed list`);
    }

    // Check network
    if (!this.policy.allowedNetworks.includes(req.network)) {
      return this.emit('deny', req, `network ${req.network} not allowed`);
    }

    // Check per-request cap
    if (req.amount > this.policy.maxPerRequest) {
      return this.emit('deny', req,
        `$${(req.amount / 100).toFixed(2)} exceeds per-request cap of $${(this.policy.maxPerRequest / 100).toFixed(2)}`);
    }

    // Check daily cap
    if (this.dailySpent + req.amount > this.policy.dailyCap) {
      return this.emit('deny', req,
        `daily spent $${((this.dailySpent + req.amount) / 100).toFixed(2)} would exceed cap of $${(this.policy.dailyCap / 100).toFixed(2)}`);
    }

    // Authorized
    this.dailySpent += req.amount;
    return this.emit('allow', req);
  }

  private emit(decision: 'allow' | 'deny', req: PaymentRequest, reason?: string): Receipt {
    const receipt: Receipt = {
      id: `rcp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
      decision,
      amount: req.amount,
      asset: req.asset,
      network: req.network,
      reason,
      agentDid: this.policy.agentDid,
      timestamp: new Date().toISOString(),
      dailySpent: this.dailySpent,
      dailyRemaining: this.policy.dailyCap - this.dailySpent,
    };
    this.receipts.push(receipt);
    return receipt;
  }

  getReceipts(): Receipt[] { return [...this.receipts]; }
  getDailySpent(): number { return this.dailySpent; }
  getDailyRemaining(): number { return this.policy.dailyCap - this.dailySpent; }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd examples/base-agent-wallet && npx tsx --test test/base-wallet.test.ts`
Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add examples/base-agent-wallet/src/base-wallet.ts examples/base-agent-wallet/test/base-wallet.test.ts
git commit -s -m "feat(base-agent-wallet): BaseAgentWallet with policy enforcement + 7 tests"
```

---

## Chunk 2: Demo Runner + CLI Entry Point

### Task 4: Create the mock paid API

Copy and adapt from `examples/x402-agent-wallet/src/paid-api.ts` with Base-specific branding.

**Files:**
- Create: `examples/base-agent-wallet/src/paid-api.ts`

- [ ] **Step 1: Write paid-api.ts**

Copy `examples/x402-agent-wallet/src/paid-api.ts` to `examples/base-agent-wallet/src/paid-api.ts`. No changes needed — same mock API works.

- [ ] **Step 2: Verify it starts**

Run: `cd examples/base-agent-wallet && npx tsx src/paid-api.ts &` then `curl -s http://localhost:3300/research/nvda | head -c 200` then `kill %1`
Expected: 402 response with x402 requirements

- [ ] **Step 3: Commit**

```bash
git add examples/base-agent-wallet/src/paid-api.ts
git commit -s -m "feat(base-agent-wallet): mock x402 paid API server"
```

---

### Task 5: Write the demo runner

The 6-scenario orchestrator that tells the story: human delegates, agent spends, policy kicks in.

**Files:**
- Create: `examples/base-agent-wallet/src/demo-runner.ts`

- [ ] **Step 1: Write demo-runner.ts**

```typescript
// src/demo-runner.ts
import { setupDelegation, type DelegationConfig } from './delegation.js';
import { BaseAgentWallet, type Receipt } from './base-wallet.js';
import { spawn, type ChildProcess } from 'child_process';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API_PORT = 3301;
const API_URL = `http://localhost:${API_PORT}`;

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

function banner(text: string): void {
  const line = '='.repeat(64);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function printReceipt(label: string, receipt: Receipt): void {
  const icon = receipt.decision === 'allow' ? '\x1b[32m ALLOW \x1b[0m' : '\x1b[31m DENY  \x1b[0m';
  console.log(`  [${icon}] ${label}`);
  console.log(`          Amount:    $${(receipt.amount / 100).toFixed(2)} ${receipt.asset} on ${receipt.network}`);
  if (receipt.reason) {
    console.log(`          Reason:    ${receipt.reason}`);
  }
  console.log(`          Daily:     $${(receipt.dailySpent / 100).toFixed(2)} spent / $${(receipt.dailyRemaining / 100).toFixed(2)} remaining`);
  console.log(`          Receipt:   ${receipt.id}`);
  console.log(`          Agent DID: ${receipt.agentDid.slice(0, 40)}...`);
  console.log('');
}

interface X402Body {
  requirements?: { amount: string; asset: string; network: string };
}

async function fetchWithPayment(
  wallet: BaseAgentWallet,
  url: string,
  label: string,
): Promise<void> {
  const res = await globalThis.fetch(url);

  if (res.status !== 402) {
    console.log(`  [INFO] ${label}: non-paid endpoint (${res.status})`);
    return;
  }

  const body: X402Body = await res.json();
  const req = body.requirements;
  if (!req) {
    console.log(`  [ERROR] ${label}: missing x402 requirements`);
    return;
  }

  const receipt = wallet.evaluatePayment({
    amount: parseInt(req.amount, 10),
    asset: req.asset,
    network: req.network,
  });

  printReceipt(label, receipt);
}

export async function runDemo(): Promise<void> {
  const procs: ChildProcess[] = [];

  try {
    banner('Bolyra Base Agent Wallet Demo');
    console.log('  Agents on Base need identity, not just wallets.\n');
    console.log('  This demo shows a human delegating a Base wallet to an AI agent');
    console.log('  with ZKP-enforced spending limits. The agent proves its');
    console.log('  authorization without revealing who authorized it.\n');

    // Phase 1: Human Delegation
    banner('Phase 1: Human Delegates Wallet to Agent');
    console.log('  Human creates identity and delegates to agent with policy...\n');

    const delegationConfig: DelegationConfig = {
      maxPerRequest: 200,       // $2.00
      dailyCap: 500,            // $5.00
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
      permissions: ['READ_DATA', 'FINANCIAL_SMALL'],
      expiryMinutes: 60,
    };

    const { humanIdentity, agentCredential, walletPolicy } = await setupDelegation(delegationConfig);

    console.log('  Human Identity:');
    console.log(`    Commitment: ${humanIdentity.commitment.toString(16).slice(0, 20)}...`);
    console.log('');
    console.log('  Agent Credential:');
    console.log(`    DID:         ${walletPolicy.agentDid}`);
    console.log(`    Permissions: READ_DATA, FINANCIAL_SMALL (<$100)`);
    console.log(`    Expires:     ${walletPolicy.expiresAt}`);
    console.log('');
    console.log('  Wallet Policy:');
    console.log(`    Max/request: $${(walletPolicy.maxPerRequest / 100).toFixed(2)}`);
    console.log(`    Daily cap:   $${(walletPolicy.dailyCap / 100).toFixed(2)}`);
    console.log(`    Assets:      ${walletPolicy.allowedAssets.join(', ')}`);
    console.log(`    Networks:    ${walletPolicy.allowedNetworks.join(', ')}`);
    console.log('');

    // Start paid API
    const apiProc = spawn('npx', ['tsx', path.join(__dirname, 'paid-api.ts')], {
      env: { ...process.env, API_PORT: String(API_PORT) },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    procs.push(apiProc);
    await sleep(3000);

    const wallet = new BaseAgentWallet(walletPolicy);

    // Phase 2: Agent Spends
    banner('Phase 2: Agent Transacts on Base');

    console.log('  Scenario 1: Agent buys NVDA research ($0.50)\n');
    await fetchWithPayment(wallet, `${API_URL}/research/nvda`, 'NVDA earnings analysis');

    console.log('  Scenario 2: Agent buys BTC summary ($0.25)\n');
    await fetchWithPayment(wallet, `${API_URL}/research/btc`, 'BTC market summary');

    console.log('  Scenario 3: Agent buys GPU inference ($1.00)\n');
    await fetchWithPayment(wallet, `${API_URL}/compute/gpu-hour`, '1h GPU inference (A100)');

    // Phase 3: Policy Enforcement
    banner('Phase 3: Policy Enforcement');

    console.log('  Scenario 4: Agent tries premium report ($5.00)\n');
    await fetchWithPayment(wallet, `${API_URL}/premium/report`, 'Premium sector report');

    console.log('  Scenario 5: Agent buys market feed ($0.10)\n');
    await fetchWithPayment(wallet, `${API_URL}/data/market-feed`, 'Real-time market feed');

    console.log('  Scenario 6: Agent buys more research ($0.50)\n');
    await fetchWithPayment(wallet, `${API_URL}/research/nvda`, 'More NVDA research');

    // Phase 4: Audit Trail
    banner('Phase 4: Audit Trail');

    const receipts = wallet.getReceipts();
    const allowed = receipts.filter(r => r.decision === 'allow');
    const denied = receipts.filter(r => r.decision === 'deny');

    console.log(`  Total transactions: ${receipts.length}`);
    console.log(`  Allowed: ${allowed.length}  |  Denied: ${denied.length}`);
    console.log(`  Total spent: $${(wallet.getDailySpent() / 100).toFixed(2)} / $${(walletPolicy.dailyCap / 100).toFixed(2)} daily cap`);
    console.log('');
    console.log('  Every decision has a signed receipt with:');
    console.log('    - Agent DID (ZKP-derived, no human identity leaked)');
    console.log('    - Amount, asset, network');
    console.log('    - Decision + reason');
    console.log('    - Running daily spend totals');
    console.log('');

    banner('Summary');
    console.log('  Agents on Base need identity, not just wallets.');
    console.log('');
    console.log('  Bolyra gives agents:');
    console.log('    1. ZK identity — prove who you are without revealing your controller');
    console.log('    2. Scoped permissions — enforced by math, not middleware');
    console.log('    3. Spend limits — per-request and daily caps');
    console.log('    4. Audit trail — signed receipts for every decision');
    console.log('');
    console.log('  Learn more: https://bolyra.ai');
    console.log('  Docs: https://bolyra.ai/playground');
    console.log('');

  } finally {
    for (const p of procs) p.kill('SIGTERM');
    await sleep(300);
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add examples/base-agent-wallet/src/demo-runner.ts
git commit -s -m "feat(base-agent-wallet): 6-scenario demo runner with narrative output"
```

---

### Task 6: Create the CLI entry point

**Files:**
- Create: `examples/base-agent-wallet/src/index.ts`

- [ ] **Step 1: Write index.ts**

```typescript
#!/usr/bin/env npx tsx
// src/index.ts
import { runDemo } from './demo-runner.js';

runDemo()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Demo failed:', err);
    process.exit(1);
  });
```

- [ ] **Step 2: Run the full demo end-to-end**

Run: `cd examples/base-agent-wallet && npm run demo`
Expected: Full 4-phase output with 4 allowed + 2 denied transactions

- [ ] **Step 3: Fix any issues found during the run**

Iterate until the demo runs cleanly with all 6 scenarios producing correct output.

- [ ] **Step 4: Commit**

```bash
git add examples/base-agent-wallet/src/index.ts
git commit -s -m "feat(base-agent-wallet): CLI entry point — npm run demo works"
```

---

## Chunk 3: Playground Tab

### Task 7: Add "Base Wallet" tab to playground.html

Add a 4th tab to the existing playground that visualizes the same human-gated spending flow in-browser. No SDK dependency — pure simulation with the same narrative.

**Files:**
- Modify: `landing/playground.html`

- [ ] **Step 1: Read the current playground.html to understand tab structure**

Run: Read `landing/playground.html` — look for the tab switching logic and the existing 3 tab panels. Note the CSS class names and JS patterns used.

- [ ] **Step 2: Add the 4th tab button**

Find the tab bar (look for `tablist` or tab buttons) and add a "Base Wallet" tab after the existing 3.

- [ ] **Step 3: Add the 4th tab panel**

Add a new panel section that shows:
- "Human Delegates" card: shows policy (max/request, daily cap, asset, network)
- "Agent Transacts" card: 6-row table showing each scenario with allow/deny status
- "Run Demo" button that animates through the scenarios one by one
- Receipt inspector showing each receipt as it's generated

Follow the existing playground's visual style (dark theme, Space Grotesk font, indigo accent, JetBrains Mono for code). Match the existing tab panel patterns exactly.

- [ ] **Step 4: Test in browser**

Run: `open landing/playground.html` (local file) and verify the 4th tab works, animation runs, receipts display correctly.

- [ ] **Step 5: Commit**

```bash
git add landing/playground.html
git commit -s -m "feat(playground): add Base Wallet tab — human-gated spending demo"
```

---

### Task 8: Update README and landing page references

**Files:**
- Create: `examples/base-agent-wallet/README.md`

- [ ] **Step 1: Write README.md**

```markdown
# @bolyra/base-agent-wallet

Human-gated spending for AI agents on Base. ZKP-enforced wallet delegation.

## Quick Start

```bash
cd examples/base-agent-wallet
npm install
npm run demo
```

## What It Does

A human delegates a Base wallet to an AI agent with:
- **ZK identity** — agent proves who it is without revealing its controller
- **Scoped permissions** — READ_DATA + FINANCIAL_SMALL (< $100)
- **Spend limits** — $2.00/request, $5.00/day
- **Audit trail** — signed receipt for every decision

The agent transacts autonomously within these limits. When it tries to
exceed them, the wallet blocks the transaction and records why.

## Demo Scenarios

| # | Request | Amount | Result |
|---|---------|--------|--------|
| 1 | NVDA research | $0.50 | ALLOW |
| 2 | BTC summary | $0.25 | ALLOW |
| 3 | GPU inference | $1.00 | ALLOW |
| 4 | Premium report | $5.00 | DENY (exceeds $2.00/request cap) |
| 5 | Market feed | $0.10 | ALLOW |
| 6 | More research | $0.50 | DENY (daily cap exceeded) |

## Interactive Demo

See it in your browser: [bolyra.ai/playground](https://bolyra.ai/playground) → Base Wallet tab
```

- [ ] **Step 2: Commit**

```bash
git add examples/base-agent-wallet/README.md
git commit -s -m "docs(base-agent-wallet): README with quick start and scenario table"
```

---

## Chunk 4: Final Verification

### Task 9: End-to-end verification

- [ ] **Step 1: Run all tests**

```bash
cd examples/base-agent-wallet && npx tsx --test test/*.test.ts
```

Expected: All tests pass (delegation + wallet tests)

- [ ] **Step 2: Run the full demo**

```bash
cd examples/base-agent-wallet && npm run demo
```

Expected: Clean 4-phase output, 4 allowed + 2 denied, no errors

- [ ] **Step 3: Verify playground tab works**

Open `landing/playground.html` in browser, click Base Wallet tab, run the demo animation.

- [ ] **Step 4: Run SDK typecheck**

```bash
cd ~/Projects/bolyra/sdk && npm run typecheck
```

Expected: No type errors

- [ ] **Step 5: Final commit with all remaining changes**

```bash
cd ~/Projects/bolyra
git status  # verify nothing unexpected
git add -p  # stage intentional files only
git commit -s -m "feat(base-agent-wallet): complete Base agent wallet integration"
```
