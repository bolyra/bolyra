# Operator Authorization Trial Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `examples/operator-trial/`, a clone-and-run example that puts one HTTP action an operator owns behind Bolyra authorization, runs three guided attempts (allow, policy deny, replay deny), signs a receipt chain, and exports a verifiable bundle.

**Architecture:** A loopback `node:http` host embeds `createGatewayMiddleware` from the published `@bolyra/gateway` (created once, so the in-memory nonce store persists across attempts). On allow it dispatches exactly one HTTP request to the operator's endpoint. Receipts are signed through the gateway's `createGatewayReceiptSigner` and appended to a JSONL file with rollback on write failure. A `runTrial()` function drives the three attempts in-process and is the single entry point for the CLI and the tests.

**Tech Stack:** TypeScript 5 (commonjs, ES2022), Node 20+, `node:test`, published `@bolyra/gateway 0.6.0`, `@bolyra/mcp 0.6.5`, `@bolyra/receipts 0.11.0`, `yaml`.

**Spec:** `docs/superpowers/specs/2026-09-13-operator-trial-design.md`. Section numbers below refer to it.

**Conventions for every task:**
- Work from `examples/operator-trial/` unless a path says otherwise.
- Every commit uses `git commit -s` (DCO sign-off is enforced by CI).
- Run `npm test` from `examples/operator-trial/` before every commit that touches `src/` or `test/`. It compiles with `tsc` then runs `node --test dist/test/*.test.js`.
- Never write header values, env values, or upstream bodies to any file or log line. When adding a log line, ask "could this contain a secret?"

---

## File map

| File | Responsibility |
|---|---|
| `examples/operator-trial/package.json` | private package, pinned published deps, scripts `trial` / `build` / `test` |
| `examples/operator-trial/tsconfig.json` | copy of the verified-actions-demo config |
| `examples/operator-trial/.gitignore` | `node_modules/`, `dist/`, `trial-out/` |
| `examples/operator-trial/trial.example.yaml` | the operator's starting point |
| `src/versions.ts` | pinned package versions, mirrored from `package.json` |
| `src/agents.ts` | permission table, `createDemoAgent`, `buildDevBundle` |
| `src/config.ts` | `loadTrialConfig`, `validateTrialConfig`, `TrialConfigError` |
| `src/echo.ts` | dry-run echo endpoint with a request counter |
| `src/audit.ts` | `Audit`: signer, JSONL append with rollback, `finalize` (bundle, verify command, secret scan) |
| `src/host.ts` | `startHost`: route check, middleware, receipts, dispatch, result channel |
| `src/trial.ts` | `runTrial`: three attempts, expectations, narration |
| `src/cli.ts` | arg parsing and exit codes |
| `test/*.test.ts` | one test file per module plus `trial.test.ts` end-to-end |
| `README.md` | operator path, config contract, honesty labels |
| `landing/operator-trial.html` | entry page |
| `.github/workflows/ci.yml` | `operator-trial` job |

---

## Chunk 1: scaffold, config, agents, echo

### Task 1: Package scaffold

**Files:**
- Create: `examples/operator-trial/package.json`
- Create: `examples/operator-trial/tsconfig.json`
- Create: `examples/operator-trial/.gitignore`
- Create: `examples/operator-trial/trial.example.yaml`
- Create: `examples/operator-trial/src/versions.ts`
- Create: `examples/operator-trial/test/versions.test.ts`

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "@bolyra/operator-trial",
  "version": "0.1.0",
  "private": true,
  "description": "Put one HTTP action you own behind a Bolyra authorization rule: three guided attempts, signed receipts, an exportable bundle.",
  "scripts": {
    "trial": "ts-node src/cli.ts",
    "build": "tsc",
    "test": "tsc && node --test dist/test/*.test.js"
  },
  "dependencies": {
    "@bolyra/gateway": "0.6.0",
    "@bolyra/mcp": "0.6.5",
    "@bolyra/receipts": "0.11.0",
    "yaml": "^2.5.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "ts-node": "^10.9.0",
    "typescript": "^5.5.0"
  }
}
```

- [ ] **Step 2: Create `tsconfig.json`** (identical to `examples/verified-actions-demo/tsconfig.json`)

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "moduleResolution": "node",
    "lib": ["ES2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "outDir": "dist",
    "rootDir": "."
  },
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

- [ ] **Step 3: Create `.gitignore`**

```
node_modules/
dist/
trial-out/
*.tsbuildinfo
```

- [ ] **Step 4: Create `trial.example.yaml`**

```yaml
# Copy to trial.yaml and edit. Use a STAGING endpoint or a reversible action:
# attempt 1 really executes.
action: refund                      # the name Bolyra gates; appears in receipts
method: POST
url: https://staging.example.com/v1/refunds
bodyFile: ./refund.json             # optional; sent byte-for-byte; not allowed with GET/HEAD/DELETE
headers:
  Authorization: "Bearer ${THEIR_TOKEN}"   # ${NAME} is replaced from the environment; unset = error
  Content-Type: application/json
requiredPermission: WRITE_DATA      # READ_DATA | WRITE_DATA | FINANCIAL_SMALL | FINANCIAL_MEDIUM
                                    # | FINANCIAL_UNLIMITED | SIGN_ON_BEHALF | SUB_DELEGATE | ACCESS_PII
```

- [ ] **Step 5: Create `src/versions.ts`**

```ts
/**
 * Pinned versions of the published packages this trial runs against. They
 * are recorded in every bundle's summary.json. test/versions.test.ts asserts
 * they match package.json so the two cannot drift.
 */
export const PACKAGES = {
  gateway: '0.6.0',
  mcp: '0.6.5',
  receipts: '0.11.0',
} as const;

/** The verifier CLI named in VERIFY.txt. */
export const CLI_VERSION = '0.9.0';

export const TRIAL_VERSION = '0.1.0';
```

- [ ] **Step 6: Write the failing test `test/versions.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PACKAGES, TRIAL_VERSION } from '../src/versions';

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8'));

test('versions.ts mirrors package.json', () => {
  assert.equal(pkg.dependencies['@bolyra/gateway'], PACKAGES.gateway);
  assert.equal(pkg.dependencies['@bolyra/mcp'], PACKAGES.mcp);
  assert.equal(pkg.dependencies['@bolyra/receipts'], PACKAGES.receipts);
  assert.equal(pkg.version, TRIAL_VERSION);
});
```

Note the `'..', '..'` — compiled tests live in `dist/test/`, so `package.json` is two levels up.

- [ ] **Step 7: Install and run the test**

Run: `cd examples/operator-trial && npm install && npm test`
Expected: `npm install` writes `package-lock.json`; the test run prints `# pass 1`.

If `npm install` is run on macOS, the lockfile may omit the `@emnapi/*` optional subtree that Linux `npm ci` needs (see `tasks/lessons.md`). Task 10 regenerates the lockfile in Docker before the final commit; a macOS lockfile is fine for local work.

- [ ] **Step 8: Commit**

```bash
git add examples/operator-trial/package.json examples/operator-trial/package-lock.json examples/operator-trial/tsconfig.json examples/operator-trial/.gitignore examples/operator-trial/trial.example.yaml examples/operator-trial/src/versions.ts examples/operator-trial/test/versions.test.ts
git commit -s -m "operator-trial: package scaffold and pinned versions"
```

### Task 2: Permission table and dev-mode agents

**Files:**
- Create: `examples/operator-trial/src/agents.ts`
- Create: `examples/operator-trial/test/agents.test.ts`

- [ ] **Step 1: Write the failing test `test/agents.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  PERMISSION_NAMES,
  CLOSED_MASK,
  requiredMask,
  withheldMask,
  withheldLabel,
  createDemoAgent,
  buildDevBundle,
} from '../src/agents';

test('closed masks match the cumulative encoding', () => {
  assert.deepEqual(
    PERMISSION_NAMES.map((n) => CLOSED_MASK[n]),
    [1n, 2n, 4n, 12n, 28n, 32n, 64n, 128n],
  );
});

test('withheld mask never satisfies the required mask (spec §3.2 soundness)', () => {
  for (const name of PERMISSION_NAMES) {
    const required = requiredMask(name);
    const withheld = withheldMask(name);
    assert.notEqual(withheld & required, required, `${name}: withheld ${withheld} would pass ${required}`);
  }
  assert.equal(withheldMask('READ_DATA'), 0n);
  assert.equal(withheldMask('FINANCIAL_UNLIMITED'), 12n);
  assert.equal(withheldLabel('READ_DATA'), 'no permissions');
  assert.equal(withheldLabel('WRITE_DATA'), 'READ_DATA only');
});

test('buildDevBundle produces a fresh nonce per call and a decodable header', () => {
  const agent = createDemoAgent('a', 2n);
  const one = buildDevBundle(agent);
  const two = buildDevBundle(agent);
  assert.notEqual(one.bundle.nonce, two.bundle.nonce);
  assert.ok(one.header.startsWith('Bolyra '));
  const decoded = JSON.parse(Buffer.from(one.header.slice(7), 'base64').toString('utf8'));
  assert.equal(decoded.credentialCommitment, agent.commitment.toString());
  assert.equal(decoded.agentProof.publicSignals[3], '2');
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/agents'`.

- [ ] **Step 3: Create `src/agents.ts`**

The bundle builder is copied from `examples/verified-actions-demo/src/agents.ts` (same dev-mode shape `@bolyra/mcp` verifies); the permission table is new.

```ts
/**
 * Simulated agent credentials + dev-mode proof bundles.
 *
 * Dev mode is the real Bolyra protocol with mock proofs: bundle shape, signal
 * layout, nonce layout, policy checks, replay protection, and receipts are
 * identical to production; only the Groth16 proof strings are mocked. This
 * is a controlled trial, not production agent authentication.
 */

import { randomBytes } from 'node:crypto';
import type { BolyraProofBundle } from '@bolyra/mcp';

/** Permission names in bit order (bit 0 first), matching @bolyra/sdk's Permission enum. */
export const PERMISSION_NAMES = [
  'READ_DATA',
  'WRITE_DATA',
  'FINANCIAL_SMALL',
  'FINANCIAL_MEDIUM',
  'FINANCIAL_UNLIMITED',
  'SIGN_ON_BEHALF',
  'SUB_DELEGATE',
  'ACCESS_PII',
] as const;
export type PermissionName = (typeof PERMISSION_NAMES)[number];

/**
 * Cumulative-closed masks: FINANCIAL_MEDIUM implies FINANCIAL_SMALL, and
 * FINANCIAL_UNLIMITED implies both. Every value here satisfies
 * validateCumulativeBitEncoding.
 */
export const CLOSED_MASK: Record<PermissionName, bigint> = {
  READ_DATA: 1n,
  WRITE_DATA: 2n,
  FINANCIAL_SMALL: 4n,
  FINANCIAL_MEDIUM: 12n,
  FINANCIAL_UNLIMITED: 28n,
  SIGN_ON_BEHALF: 32n,
  SUB_DELEGATE: 64n,
  ACCESS_PII: 128n,
};

/** The policy's requireBitmask for a required permission name. */
export function requiredMask(name: PermissionName): bigint {
  return CLOSED_MASK[name];
}

/**
 * The withheld credential's mask: the closed mask of the previous row, or 0
 * for READ_DATA. A lower row's mask never contains the required row's own
 * bit, so checkToolPolicy's `(mask & required) === required` always fails.
 */
export function withheldMask(name: PermissionName): bigint {
  const i = PERMISSION_NAMES.indexOf(name);
  return i === 0 ? 0n : CLOSED_MASK[PERMISSION_NAMES[i - 1]];
}

/** Narration label for the withheld credential. */
export function withheldLabel(name: PermissionName): string {
  const i = PERMISSION_NAMES.indexOf(name);
  return i === 0 ? 'no permissions' : `${PERMISSION_NAMES[i - 1]} only`;
}

export interface DemoAgent {
  /** Narration label. */
  name: string;
  /** Credential commitment, identifies the credential in the static map. */
  commitment: bigint;
  /** Cumulative permission bitmask granted to this credential. */
  permissionBitmask: bigint;
}

export function createDemoAgent(name: string, permissionBitmask: bigint): DemoAgent {
  return {
    name,
    commitment: BigInt('0x' + randomBytes(16).toString('hex')),
    permissionBitmask,
  };
}

export interface AgentAuth {
  /** Value for the Authorization header ("Bolyra <base64 bundle>"). */
  header: string;
  bundle: BolyraProofBundle;
}

/** Production nonce layout: (unix_seconds << 64) | 64 bits of entropy. */
function freshNonce(nowSeconds: bigint): bigint {
  const entropy = BigInt('0x' + randomBytes(8).toString('hex'));
  return (nowSeconds << 64n) | entropy;
}

/**
 * Build a dev-mode proof bundle. Each call generates a fresh nonce; reusing a
 * header is a replay and the gateway middleware rejects it.
 */
export function buildDevBundle(agent: DemoAgent): AgentAuth {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const nonce = freshNonce(now);
  const mockProofStrings = Array.from({ length: 8 }, () =>
    BigInt('0x' + randomBytes(4).toString('hex')).toString(),
  );

  const bundle: BolyraProofBundle = {
    v: 1,
    humanProof: {
      proof: mockProofStrings as never,
      publicSignals: ['0', '0', '0', '0', nonce.toString()],
    },
    // AgentPolicy public signal layout:
    // [0] agentMerkleRoot, [1] nullifierHash, [2] scopeCommitment,
    // [3] requiredScopeMask, [4] currentTimestamp, [5] sessionNonce
    agentProof: {
      proof: mockProofStrings as never,
      publicSignals: [
        '0',
        '0',
        agent.commitment.toString(),
        agent.permissionBitmask.toString(),
        now.toString(),
        nonce.toString(),
      ],
    },
    nonce: nonce.toString(),
    credentialCommitment: agent.commitment.toString(),
    _dev: true,
  };

  const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
  return { header: `Bolyra ${encoded}`, bundle };
}

/** Render a bitmask as binary with a "b" suffix, e.g. 3n -> "11b". */
export function fmtMask(mask: bigint): string {
  return mask.toString(2) + 'b';
}
```

- [ ] **Step 4: Run the tests**

Run: `npm test`
Expected: `# pass 4`, `# fail 0`.

- [ ] **Step 5: Commit**

```bash
git add examples/operator-trial/src/agents.ts examples/operator-trial/test/agents.test.ts
git commit -s -m "operator-trial: permission table and dev-mode agents"
```

### Task 3: Trial config contract

**Files:**
- Create: `examples/operator-trial/src/config.ts`
- Create: `examples/operator-trial/test/config.test.ts`

- [ ] **Step 1: Write the failing test `test/config.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { validateTrialConfig, loadTrialConfig, TrialConfigError } from '../src/config';

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'trial-config-'));

function valid(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    action: 'refund',
    method: 'POST',
    url: 'https://staging.example.com/v1/refunds',
    requiredPermission: 'WRITE_DATA',
    ...overrides,
  };
}

function rejects(input: Record<string, unknown>, fragment: string, env: NodeJS.ProcessEnv = {}) {
  assert.throws(
    () => validateTrialConfig(input, base, env),
    (err: unknown) => err instanceof TrialConfigError && err.message.includes(fragment),
    `expected TrialConfigError mentioning "${fragment}"`,
  );
}

test('accepts a minimal valid config', () => {
  const cfg = validateTrialConfig(valid(), base, {});
  assert.equal(cfg.action, 'refund');
  assert.equal(cfg.method, 'POST');
  assert.equal(cfg.url.hostname, 'staging.example.com');
  assert.deepEqual(cfg.headers, {});
  assert.equal(cfg.body, undefined);
  assert.equal(cfg.requiredPermission, 'WRITE_DATA');
  assert.deepEqual(cfg.secrets, []);
});

test('rejects unknown keys', () => rejects(valid({ extra: 1 }), 'unknown key: extra'));
test('rejects a bad action name', () => rejects(valid({ action: 'Refund!' }), 'action'));
test('rejects a bad method', () => rejects(valid({ method: 'OPTIONS' }), 'method'));
test('rejects a non-http scheme', () => rejects(valid({ url: 'ftp://x' }), 'scheme'));
test('rejects credentials in the URL', () => rejects(valid({ url: 'https://u:p@x.example/' }), 'credentials'));
test('rejects an unknown permission', () => rejects(valid({ requiredPermission: 'ROOT' }), 'requiredPermission'));

test('substitutes ${ENV} in header values and records the secret', () => {
  const cfg = validateTrialConfig(
    valid({ headers: { Authorization: 'Bearer ${T}', 'X-Static': 'plain' } }),
    base,
    { T: 'sekrit-123' },
  );
  assert.equal(cfg.headers.Authorization, 'Bearer sekrit-123');
  assert.deepEqual(cfg.secrets, ['sekrit-123', 'Bearer sekrit-123', 'plain']);
});

test('fails on an unset ${ENV} before anything else runs (spec test 9)', () => {
  rejects(valid({ headers: { Authorization: 'Bearer ${MISSING}' } }), 'MISSING', {});
});

test('rejects bodyFile with GET, HEAD, DELETE', () => {
  const bodyPath = path.join(base, 'b.json');
  fs.writeFileSync(bodyPath, '{}');
  for (const method of ['GET', 'HEAD', 'DELETE']) {
    rejects(valid({ method, bodyFile: 'b.json' }), 'bodyFile');
  }
});

test('reads bodyFile relative to the config directory, byte for byte', () => {
  fs.writeFileSync(path.join(base, 'body.bin'), Buffer.from([0, 255, 10, 13]));
  const cfg = validateTrialConfig(valid({ bodyFile: 'body.bin' }), base, {});
  assert.deepEqual(cfg.body, Buffer.from([0, 255, 10, 13]));
});

test('loadTrialConfig parses YAML and JSON', () => {
  const y = path.join(base, 'trial.yaml');
  fs.writeFileSync(y, 'action: refund\nmethod: POST\nurl: https://x.example/r\nrequiredPermission: READ_DATA\n');
  assert.equal(loadTrialConfig(y, {}).requiredPermission, 'READ_DATA');
  const j = path.join(base, 'trial.json');
  fs.writeFileSync(j, JSON.stringify(valid()));
  assert.equal(loadTrialConfig(j, {}).action, 'refund');
  assert.throws(() => loadTrialConfig(path.join(base, 'nope.yaml'), {}), TrialConfigError);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/config'`.

- [ ] **Step 3: Create `src/config.ts`**

```ts
/**
 * The trial config contract (spec §3.5). Every violation throws
 * TrialConfigError naming the key. ${NAME} substitution is literal
 * replacement from the environment, applies to header values only, and
 * fails on an unset variable. This is deliberately stricter than
 * @bolyra/gateway's substituteEnvVars, which leaves unset references in place.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { PERMISSION_NAMES } from './agents';
import type { PermissionName } from './agents';

export class TrialConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrialConfigError';
  }
}

export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type Method = (typeof METHODS)[number];

const BODYLESS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'DELETE']);
const ACTION_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'action',
  'method',
  'url',
  'headers',
  'bodyFile',
  'requiredPermission',
]);

export interface TrialConfig {
  action: string;
  method: Method;
  url: URL;
  /** Header values after ${ENV} substitution. Never log these. */
  headers: Record<string, string>;
  /** Literal request body, sent byte for byte. */
  body?: Buffer;
  requiredPermission: PermissionName;
  /**
   * Values the secret scan must never find in the bundle: every substituted
   * environment value and every resolved header value (deduplicated, empty
   * strings dropped).
   */
  secrets: string[];
}

export function loadTrialConfig(filePath: string, env: NodeJS.ProcessEnv = process.env): TrialConfig {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new TrialConfigError(`config file not found: ${resolved}`);
  }
  const raw = fs.readFileSync(resolved, 'utf8');
  let parsed: unknown;
  try {
    parsed = resolved.toLowerCase().endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
  } catch (err) {
    throw new TrialConfigError(`config file could not be parsed: ${(err as Error).message}`);
  }
  return validateTrialConfig(parsed, path.dirname(resolved), env);
}

export function validateTrialConfig(
  input: unknown,
  baseDir: string,
  env: NodeJS.ProcessEnv,
): TrialConfig {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TrialConfigError('config must be a map of keys');
  }
  const obj = input as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!ALLOWED_KEYS.has(key)) throw new TrialConfigError(`unknown key: ${key}`);
  }

  const action = obj.action;
  if (typeof action !== 'string' || !ACTION_RE.test(action)) {
    throw new TrialConfigError('action: required; must match ^[a-z][a-z0-9_-]{0,63}$');
  }

  const method = obj.method;
  if (typeof method !== 'string' || !(METHODS as readonly string[]).includes(method)) {
    throw new TrialConfigError(`method: required; one of ${METHODS.join(' ')}`);
  }

  if (typeof obj.url !== 'string') throw new TrialConfigError('url: required string');
  let url: URL;
  try {
    url = new URL(obj.url);
  } catch {
    throw new TrialConfigError('url: not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TrialConfigError('url: scheme must be http or https');
  }
  if (url.username !== '' || url.password !== '') {
    throw new TrialConfigError('url: credentials in the URL are not allowed');
  }

  const envValues: string[] = [];
  const headers: Record<string, string> = {};
  if (obj.headers !== undefined) {
    if (typeof obj.headers !== 'object' || obj.headers === null || Array.isArray(obj.headers)) {
      throw new TrialConfigError('headers: must be a map of header name to value');
    }
    for (const [name, value] of Object.entries(obj.headers as Record<string, unknown>)) {
      if (!HEADER_NAME_RE.test(name)) throw new TrialConfigError(`headers.${name}: invalid header name`);
      if (typeof value !== 'string') throw new TrialConfigError(`headers.${name}: value must be a string`);
      headers[name] = substituteEnv(value, env, `headers.${name}`, envValues);
    }
  }

  let body: Buffer | undefined;
  if (obj.bodyFile !== undefined) {
    if (typeof obj.bodyFile !== 'string') throw new TrialConfigError('bodyFile: must be a string path');
    if (BODYLESS.has(method)) throw new TrialConfigError(`bodyFile: not allowed with method ${method}`);
    const bodyPath = path.resolve(baseDir, obj.bodyFile);
    if (!fs.existsSync(bodyPath)) throw new TrialConfigError(`bodyFile: not found: ${bodyPath}`);
    body = fs.readFileSync(bodyPath);
  }

  const rp = obj.requiredPermission;
  if (typeof rp !== 'string' || !(PERMISSION_NAMES as readonly string[]).includes(rp)) {
    throw new TrialConfigError(`requiredPermission: required; one of ${PERMISSION_NAMES.join(' ')}`);
  }

  const secrets = dedupe([...envValues, ...Object.values(headers)]).filter((s) => s.length > 0);

  return {
    action,
    method: method as Method,
    url,
    headers,
    body,
    requiredPermission: rp as PermissionName,
    secrets,
  };
}

/** Literal ${NAME} replacement. Throws on an unset variable. */
export function substituteEnv(
  value: string,
  env: NodeJS.ProcessEnv,
  where: string,
  collected: string[],
): string {
  return value.replace(/\$\{([^}]+)\}/g, (_match, name: string) => {
    const v = env[name];
    if (v === undefined) {
      throw new TrialConfigError(`${where}: environment variable ${name} is not set`);
    }
    collected.push(v);
    return v;
  });
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values));
}
```

- [ ] **Step 4: Run the tests**

Run: `npm test`
Expected: all pass (`# fail 0`).

- [ ] **Step 5: Commit**

```bash
git add examples/operator-trial/src/config.ts examples/operator-trial/test/config.test.ts
git commit -s -m "operator-trial: config contract with strict env substitution"
```

### Task 4: Dry-run echo endpoint

**Files:**
- Create: `examples/operator-trial/src/echo.ts`
- Create: `examples/operator-trial/test/echo.test.ts`

- [ ] **Step 1: Write the failing test `test/echo.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { startEcho } from '../src/echo';

test('echo counts requests and returns the configured status', async () => {
  const echo = await startEcho();
  try {
    const r1 = await fetch(echo.url, { method: 'POST', body: '{}' });
    assert.equal(r1.status, 200);
    assert.deepEqual(await r1.json(), { echoed: true });
    await fetch(echo.url, { method: 'POST', body: '{}' });
    assert.equal(echo.requestCount, 2);
  } finally {
    await echo.close();
  }
});

test('echo can answer with a redirect that is not followed', async () => {
  const echo = await startEcho({ status: 302 });
  try {
    const r = await fetch(echo.url, { method: 'POST', body: '{}', redirect: 'manual' });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/elsewhere');
    assert.equal(echo.requestCount, 1);
  } finally {
    await echo.close();
  }
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/echo'`.

- [ ] **Step 3: Create `src/echo.ts`**

```ts
/**
 * Dry-run endpoint (spec §3.4): a loopback server that counts requests and
 * answers with a configurable status. It is the CI path and the operator's
 * first run, so the mechanics are visible before a real endpoint is touched.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface EchoOptions {
  /** HTTP status to answer with (default 200). 3xx adds a Location header. */
  status?: number;
}

export interface EchoServer {
  url: string;
  readonly requestCount: number;
  close(): Promise<void>;
}

export async function startEcho(opts: EchoOptions = {}): Promise<EchoServer> {
  const status = opts.status ?? 200;
  let requestCount = 0;

  const server = http.createServer((req, res) => {
    requestCount += 1;
    req.resume();
    req.on('end', () => {
      const body = JSON.stringify({ echoed: true });
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
      };
      if (status >= 300 && status < 400) headers.location = '/elsewhere';
      res.writeHead(status, headers);
      res.end(body);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}/echo`,
    get requestCount() {
      return requestCount;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
```

- [ ] **Step 4: Run the tests**

Run: `npm test`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add examples/operator-trial/src/echo.ts examples/operator-trial/test/echo.test.ts
git commit -s -m "operator-trial: dry-run echo endpoint"
```

---

## Chunk 2: audit, host, trial, cli

### Task 5: Audit — signer, append with rollback, finalize

**Files:**
- Create: `examples/operator-trial/src/audit.ts`
- Create: `examples/operator-trial/test/audit.test.ts`

The signer comes from `createGatewayReceiptSigner(gatewayConfig)` in `@bolyra/gateway` (ephemeral key, hash-chained via `ReceiptChain`, exposes the signer address). `audit.ts` owns the file: it appends each signed receipt, tracks `committedBytes`, and rolls the file back on a failed append (spec §3.3 write-failure rule).

- [ ] **Step 1: Write the failing test `test/audit.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyReceipt, verifyReceiptChain } from '@bolyra/receipts';
import type { AuthReceiptInput } from '@bolyra/receipts';
import { Audit, AuditWriteError } from '../src/audit';
import type { FinalizeInput } from '../src/audit';
import { buildGatewayConfig } from '../src/gateway-config';
import { createDemoAgent } from '../src/agents';

function tmp(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trial-audit-')), 'run');
}

function gatewayConfig() {
  return buildGatewayConfig('refund', 2n, createDemoAgent('g', 2n), createDemoAgent('w', 1n));
}

function input(reason: string, nonce: string): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:dev:test',
    actingDid: 'did:bolyra:dev:test',
    credentialCommitment: '1',
    effectiveCommitment: '1',
    allowed: true,
    reasonCode: reason,
    score: 100,
    permissionBitmask: '2',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce,
  };
}

function finalizeInput(overrides: Partial<FinalizeInput> = {}): FinalizeInput {
  return {
    attemptsOk: true,
    attempts: [],
    dispatchCounts: [1, 0, 0],
    dryRun: true,
    action: { name: 'refund', method: 'POST', host: '127.0.0.1:1', path: '/x' },
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    secrets: [],
    ...overrides,
  };
}

test('records a verifiable chain and writes the bundle', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  assert.ok(fs.existsSync(path.join(dir, 'signer.json')));
  const signerJson = JSON.parse(fs.readFileSync(path.join(dir, 'signer.json'), 'utf8'));
  assert.equal(signerJson.ephemeral, true);
  assert.equal(signerJson.signer, audit.signerInfo.signer);

  const r1 = audit.record(input('allowed', '1'));
  const r2 = audit.record(input('denied', '2'));
  assert.ok(verifyReceipt(r1, audit.signerInfo.signer));
  assert.ok(verifyReceipt(r2, audit.signerInfo.signer));

  const fin = audit.finalize(finalizeInput());
  assert.equal(fin.ok, true);
  assert.equal(fin.receiptCount, 2);
  const chain = verifyReceiptChain(audit.readReceipts(), { expectedSigner: audit.signerInfo.signer, expectedCount: 2 });
  assert.equal(chain.ok, true);
  assert.equal(fin.headReceiptHash, chain.headHash);
  const verify = fs.readFileSync(path.join(dir, 'VERIFY.txt'), 'utf8');
  assert.match(verify, /npx @bolyra\/cli@0\.9\.0 receipt verify-chain \.\/receipts\.jsonl/);
  assert.match(verify, new RegExp(`--signer ${audit.signerInfo.signer}`));
  assert.match(verify, /--expect-count 2/);
  assert.match(verify, new RegExp(`--expect-head ${chain.headHash}`));
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.receiptCount, 2);
  assert.equal(summary.note, 'unsigned observations; signer key is ephemeral');
});

test('refuses to start in an existing run directory', () => {
  const dir = tmp();
  fs.mkdirSync(dir, { recursive: true });
  assert.throws(() => new Audit({ runDir: dir, gatewayConfig: gatewayConfig() }), /already exists/);
});

test('partial append failure rolls back to the committed prefix and breaks the chain (spec test 11)', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        if (calls === 2) {
          fs.appendFileSync(p, data.slice(0, Math.floor(data.length / 2)));
          throw new Error('disk full');
        }
        fs.appendFileSync(p, data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  assert.throws(() => audit.record(input('denied', '2')), (e: unknown) => e instanceof AuditWriteError && /disk full/.test(e.message));
  assert.equal(audit.fileState, 'broken');
  assert.throws(() => audit.record(input('denied', '3')), /chain broken by earlier write failure/);
  const receipts = audit.readReceipts();
  assert.equal(receipts.length, 1);
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, 1);
  assert.match(fs.readFileSync(path.join(dir, 'VERIFY.txt'), 'utf8'), /--expect-count 1/);
});

test('failed truncate marks the file unverifiable; finalize does not parse it (spec test 13)', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        if (calls === 2) {
          fs.appendFileSync(p, data.slice(0, 10));
          throw new Error('disk full');
        }
        fs.appendFileSync(p, data);
      },
      truncateSync() {
        throw new Error('truncate failed');
      },
    },
  });
  audit.record(input('allowed', '1'));
  assert.throws(() => audit.record(input('denied', '2')), AuditWriteError);
  assert.equal(audit.fileState, 'unverifiable');
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, null);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.fileState, 'unverifiable');
});

test('zero receipts: failure summary, no VERIFY.txt (spec test 10)', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, 0);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8')).receiptCount, 0);
});

test('secret scan deletes the directory on a hit', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  audit.record(input('allowed sekrit-xyz', '1'));
  const fin = audit.finalize(finalizeInput({ secrets: ['sekrit-xyz'] }));
  assert.equal(fin.ok, false);
  assert.match(fin.reason ?? '', /receipts\.jsonl/);
  assert.equal(fs.existsSync(dir), false);
});
```

This test imports `buildGatewayConfig` from `src/gateway-config.ts`, created in Step 3 of this task. Keeping the gateway config builder in its own file lets `audit.ts`, `host.ts`, `trial.ts`, and the tests share it.

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/audit'`.

- [ ] **Step 3: Create `src/gateway-config.ts`**

```ts
/**
 * The complete GatewayConfig the embedded middleware needs (spec §3.1).
 * Nothing is loaded from a gateway YAML. `port` and `target` are placeholders:
 * the middleware is embedded directly and never proxies MCP. validateConfig is
 * not called (it would reject port 0), and buildCredentialRegistry parses the
 * static map without validating closure; closure comes from agents.ts.
 */

import type { GatewayConfig } from '@bolyra/gateway';
import type { DemoAgent } from './agents';

export function buildGatewayConfig(
  actionName: string,
  requiredMask: bigint,
  granted: DemoAgent,
  withheld: DemoAgent,
): GatewayConfig {
  return {
    target: 'http://127.0.0.1:1/unused',
    port: 0,
    network: 'base-sepolia',
    devMode: true,
    credentials: {
      type: 'static',
      map: {
        [granted.commitment.toString()]: { permissionBitmask: granted.permissionBitmask.toString() },
        [withheld.commitment.toString()]: { permissionBitmask: withheld.permissionBitmask.toString() },
      },
    },
    tools: { [actionName]: { requireBitmask: Number(requiredMask) } },
    nonce: { store: 'memory', maxProofAge: 300 },
    // The trial signs its own receipts through createGatewayReceiptSigner,
    // which reads issuer/keyId from here and generates an ephemeral key.
    receipts: { enabled: false, output: 'stdout', issuer: 'operator-trial', keyId: 'trial-k1' },
    health: { enabled: false, path: '/healthz' },
  };
}
```

- [ ] **Step 4: Create `src/audit.ts`**

```ts
/**
 * Receipts and the result bundle (spec §3.3).
 *
 * Signing goes through @bolyra/gateway's createGatewayReceiptSigner: an
 * ephemeral ES256K key, hash-chained via ReceiptChain. This module owns the
 * file. ReceiptChain.sign advances its state BEFORE the append, so a signed
 * receipt that fails to persist would leave a gap every later receipt chains
 * past. On the first append failure the file is rolled back to the last
 * committed byte and no further receipts are signed; the file then holds an
 * intact prefix, and that prefix is all the bundle describes.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createGatewayReceiptSigner } from '@bolyra/gateway';
import type { GatewayConfig, GatewayReceiptSigner } from '@bolyra/gateway';
import { verifyReceiptChain } from '@bolyra/receipts';
import type { AuthReceiptInput, SignedReceipt } from '@bolyra/receipts';
import { CLI_VERSION, PACKAGES, TRIAL_VERSION } from './versions';

export type FileState = 'ok' | 'broken' | 'unverifiable';

export class AuditWriteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditWriteError';
  }
}

/** Injectable file operations, for the write-failure tests. */
export interface AuditIo {
  appendFileSync(filePath: string, data: string): void;
  truncateSync(filePath: string, length: number): void;
}

export interface AuditOptions {
  runDir: string;
  gatewayConfig: GatewayConfig;
  io?: Partial<AuditIo>;
}

export interface SignerInfo {
  issuer: string;
  keyId: string;
  alg: 'ES256K';
  signer: string;
  ephemeral: true;
}

/** One attempt as recorded in summary.json. Mirrors host.ts's shape plus n/credential. */
export interface SummaryAttempt {
  n: number;
  credential: string;
  decision: 'allow' | 'deny';
  stage?: string;
  reason: string;
  httpStatus: number;
  dispatched: boolean;
  upstreamStatus: number | null;
  outcome: string;
  receiptId: string | null;
  receiptError?: string;
}

export interface FinalizeInput {
  attemptsOk: boolean;
  attempts: SummaryAttempt[];
  dispatchCounts: [number, number, number];
  dryRun: boolean;
  action: { name: string; method: string; host: string; path: string };
  startedAt: string;
  finishedAt: string;
  /** Values that must not appear anywhere in the bundle. */
  secrets: string[];
}

export interface FinalizeResult {
  ok: boolean;
  reason?: string;
  receiptCount: number | null;
  headReceiptHash: string | null;
  verifyCommand: string | null;
}

export class Audit {
  readonly runDir: string;
  readonly receiptsPath: string;
  readonly signerInfo: SignerInfo;
  fileState: FileState = 'ok';
  private committedBytes = 0;
  private readonly signer: GatewayReceiptSigner;
  private readonly io: AuditIo;

  constructor(opts: AuditOptions) {
    if (fs.existsSync(opts.runDir)) {
      throw new Error(`run directory already exists: ${opts.runDir}`);
    }
    this.runDir = opts.runDir;
    this.receiptsPath = path.join(opts.runDir, 'receipts.jsonl');
    this.io = {
      appendFileSync: opts.io?.appendFileSync ?? ((p, d) => fs.appendFileSync(p, d)),
      truncateSync: opts.io?.truncateSync ?? ((p, l) => fs.truncateSync(p, l)),
    };

    this.signer = createGatewayReceiptSigner(opts.gatewayConfig);
    if (!this.signer.ephemeral) {
      throw new Error('trial signer must be ephemeral; do not configure receipts.privateKey');
    }
    this.signerInfo = {
      issuer: this.signer.issuer,
      keyId: this.signer.keyId,
      alg: 'ES256K',
      signer: this.signer.signer,
      ephemeral: true,
    };

    fs.mkdirSync(opts.runDir, { recursive: true });
    fs.writeFileSync(path.join(opts.runDir, 'signer.json'), JSON.stringify(this.signerInfo, null, 2) + '\n');
    fs.writeFileSync(this.receiptsPath, '');
  }

  /** Sign and persist one decision. Throws AuditWriteError after rolling back a failed append. */
  record(input: AuthReceiptInput): SignedReceipt {
    if (this.fileState !== 'ok') {
      throw new AuditWriteError('chain broken by earlier write failure');
    }
    const receipt = this.signer.sign(input);
    const line = JSON.stringify(receipt) + '\n';
    try {
      this.io.appendFileSync(this.receiptsPath, line);
    } catch (err) {
      this.fileState = 'broken';
      try {
        this.io.truncateSync(this.receiptsPath, this.committedBytes);
      } catch {
        this.fileState = 'unverifiable';
      }
      throw new AuditWriteError(`receipt write failed: ${(err as Error).message}`);
    }
    this.committedBytes += Buffer.byteLength(line);
    return receipt;
  }

  readReceipts(): SignedReceipt[] {
    const raw = fs.readFileSync(this.receiptsPath, 'utf8').trim();
    if (raw === '') return [];
    return raw.split('\n').map((l) => JSON.parse(l) as SignedReceipt);
  }

  finalize(input: FinalizeInput): FinalizeResult {
    // Step 0: scan whatever exists before anything else is decided, so a kept
    // directory is never an unscanned directory.
    const early = this.scanSecrets(input.secrets);
    if (early) return this.deleteAndFail(early);

    const base = {
      trialVersion: TRIAL_VERSION,
      packages: PACKAGES,
      dryRun: input.dryRun,
      action: input.action,
      attempts: input.attempts,
      dispatchCounts: input.dispatchCounts,
      startedAt: input.startedAt,
      finishedAt: input.finishedAt,
      fileState: this.fileState,
      note: 'unsigned observations; signer key is ephemeral',
    };

    if (this.fileState === 'unverifiable') {
      this.writeSummary({ ...base, ok: false, receiptCount: null, headReceiptHash: null });
      return this.scanAfter(input.secrets, { ok: false, reason: 'receipt file unverifiable', receiptCount: null, headReceiptHash: null, verifyCommand: null });
    }

    const receipts = this.readReceipts();
    if (receipts.length === 0) {
      this.writeSummary({ ...base, ok: false, receiptCount: 0, headReceiptHash: null });
      return this.scanAfter(input.secrets, { ok: false, reason: 'no receipts were written', receiptCount: 0, headReceiptHash: null, verifyCommand: null });
    }

    const chain = verifyReceiptChain(receipts, {
      expectedSigner: this.signerInfo.signer,
      expectedCount: receipts.length,
    });
    if (!chain.ok || !chain.headHash) {
      const issues = chain.issues.map((i) => i.code).join(', ');
      return { ok: false, reason: `receipt chain failed verification: ${issues}`, receiptCount: receipts.length, headReceiptHash: null, verifyCommand: null };
    }

    const ok = input.attemptsOk && this.fileState === 'ok';
    this.writeSummary({ ...base, ok, receiptCount: receipts.length, headReceiptHash: chain.headHash });
    const verifyCommand =
      `npx @bolyra/cli@${CLI_VERSION} receipt verify-chain ./receipts.jsonl ` +
      `--signer ${this.signerInfo.signer} --expect-count ${receipts.length} --expect-head ${chain.headHash}`;
    fs.writeFileSync(path.join(this.runDir, 'VERIFY.txt'), verifyCommand + '\n');

    return this.scanAfter(input.secrets, { ok, receiptCount: receipts.length, headReceiptHash: chain.headHash, verifyCommand });
  }

  private writeSummary(summary: Record<string, unknown>): void {
    fs.writeFileSync(path.join(this.runDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  }

  /** Returns "<file>" naming the first file containing a secret, or null. */
  private scanSecrets(secrets: string[]): string | null {
    if (secrets.length === 0 || !fs.existsSync(this.runDir)) return null;
    for (const name of fs.readdirSync(this.runDir)) {
      const content = fs.readFileSync(path.join(this.runDir, name), 'utf8');
      for (const s of secrets) {
        if (content.includes(s)) return name;
      }
    }
    return null;
  }

  private scanAfter(secrets: string[], result: FinalizeResult): FinalizeResult {
    const hit = this.scanSecrets(secrets);
    return hit ? this.deleteAndFail(hit) : result;
  }

  private deleteAndFail(file: string): FinalizeResult {
    fs.rmSync(this.runDir, { recursive: true, force: true });
    return {
      ok: false,
      reason: `a resolved secret value was found in ${file}; the run directory was deleted`,
      receiptCount: null,
      headReceiptHash: null,
      verifyCommand: null,
    };
  }
}
```

- [ ] **Step 5: Run the tests**

Run: `npm test`
Expected: all pass. If `createGatewayReceiptSigner` is reported as not exported, stop: the installed `@bolyra/gateway` is not 0.6.0. Check `node -p "require('@bolyra/gateway/package.json').version"`.

- [ ] **Step 6: Commit**

```bash
git add examples/operator-trial/src/gateway-config.ts examples/operator-trial/src/audit.ts examples/operator-trial/test/audit.test.ts
git commit -s -m "operator-trial: audit with append rollback and bundle finalize"
```

### Task 6: Host — the authorization boundary

**Files:**
- Create: `examples/operator-trial/src/host.ts`
- Create: `examples/operator-trial/test/host.test.ts`

- [ ] **Step 1: Write the failing test `test/host.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyReceipt } from '@bolyra/receipts';
import { Audit } from '../src/audit';
import { buildGatewayConfig } from '../src/gateway-config';
import { createDemoAgent, buildDevBundle, requiredMask, withheldMask, PERMISSION_NAMES } from '../src/agents';
import type { PermissionName } from '../src/agents';
import type { TrialConfig } from '../src/config';
import { startEcho } from '../src/echo';
import { startHost } from '../src/host';
import type { TrialHost } from '../src/host';

interface Fixture {
  host: TrialHost;
  audit: Audit;
  granted: ReturnType<typeof createDemoAgent>;
  withheld: ReturnType<typeof createDemoAgent>;
  echo: Awaited<ReturnType<typeof startEcho>>;
  close(): Promise<void>;
}

async function fixture(permission: PermissionName = 'WRITE_DATA', echoStatus = 200, audit?: Partial<{ io: ConstructorParameters<typeof Audit>[0]['io'] }>): Promise<Fixture> {
  const echo = await startEcho({ status: echoStatus });
  const granted = createDemoAgent('granted', requiredMask(permission));
  const withheld = createDemoAgent('withheld', withheldMask(permission));
  const gatewayConfig = buildGatewayConfig('refund', requiredMask(permission), granted, withheld);
  const config: TrialConfig = {
    action: 'refund',
    method: 'POST',
    url: new URL(echo.url),
    headers: {},
    requiredPermission: permission,
    secrets: [],
  };
  const runDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trial-host-')), 'run');
  const auditInstance = new Audit({ runDir, gatewayConfig, io: audit?.io });
  const host = await startHost({ config, gatewayConfig, audit: auditInstance });
  return {
    host,
    audit: auditInstance,
    granted,
    withheld,
    echo,
    close: async () => {
      await host.close();
      await echo.close();
    },
  };
}

async function call(host: TrialHost, action: string, authHeader?: string, method = 'POST') {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (authHeader) headers.authorization = authHeader;
  const res = await fetch(`${host.url}/action/${action}`, { method, headers, body: method === 'GET' ? undefined : '{}' });
  await res.arrayBuffer();
  return res.status;
}

test('allow: dispatched once, receipted, upstream status recorded', async () => {
  const f = await fixture();
  try {
    const status = await call(f.host, 'refund', buildDevBundle(f.granted).header);
    assert.equal(status, 200);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'allow');
    assert.equal(r.dispatched, true);
    assert.equal(r.upstreamStatus, 200);
    assert.equal(r.outcome, 'completed');
    assert.equal(f.echo.requestCount, 1);
    assert.equal(f.host.dispatchCount, 1);
    const receipts = f.audit.readReceipts();
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].id, r.receiptId);
    assert.ok(verifyReceipt(receipts[0], f.audit.signerInfo.signer));
    assert.match(receipts[0].payload.decision.reasonCode ?? '', /allowed \| action=refund POST 127\.0\.0\.1:\d+\/echo/);
  } finally {
    await f.close();
  }
});

test('policy deny: 403, not dispatched, receipted with the denial reason', async () => {
  const f = await fixture();
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.withheld).header), 403);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'deny');
    assert.equal(r.stage, 'policy_denied');
    assert.equal(r.dispatched, false);
    assert.equal(r.outcome, 'not_dispatched');
    assert.equal(f.echo.requestCount, 0);
    const receipts = f.audit.readReceipts();
    assert.equal(receipts[0].payload.decision.allowed, false);
    assert.match(receipts[0].payload.decision.reasonCode ?? '', /policy_denied.*\| action=refund/);
  } finally {
    await f.close();
  }
});

test('replay: same header twice is 401 nonce reuse, receipt carries a derived DID', async () => {
  const f = await fixture();
  try {
    const auth = buildDevBundle(f.granted).header;
    assert.equal(await call(f.host, 'refund', auth), 200);
    await f.host.nextResult();
    assert.equal(await call(f.host, 'refund', auth), 401);
    const r = await f.host.nextResult();
    assert.equal(r.stage, 'verification_failed');
    assert.match(r.reason, /Nonce already used/);
    assert.equal(r.dispatched, false);
    assert.equal(f.echo.requestCount, 1);
    const [, replay] = f.audit.readReceipts();
    assert.notEqual(replay.payload.subject.rootDid, '');
    assert.match(replay.payload.subject.rootDid, /^did:bolyra:dev:/);
  } finally {
    await f.close();
  }
});

test('route bypass: other paths and methods are 404 and not receipted (spec test 4)', async () => {
  const f = await fixture();
  try {
    assert.equal(await call(f.host, 'other', buildDevBundle(f.granted).header), 404);
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header, 'GET'), 404);
    assert.equal(f.audit.readReceipts().length, 0);
    assert.equal(f.host.results.length, 0);
  } finally {
    await f.close();
  }
});

test('credential mismatch: forged mask is 401 credential_mismatch (spec test 5)', async () => {
  const f = await fixture('WRITE_DATA');
  try {
    const forged = buildDevBundle({ ...f.granted, permissionBitmask: f.granted.permissionBitmask | 128n });
    assert.equal(await call(f.host, 'refund', forged.header), 401);
    const r = await f.host.nextResult();
    assert.equal(r.stage, 'credential_binding_failed');
    assert.match(r.reason, /^credential_mismatch/);
    assert.equal(r.dispatched, false);
    assert.equal(f.audit.readReceipts().length, 1);
  } finally {
    await f.close();
  }
});

test('bundle-less denial is receipted anonymously (spec test 12)', async () => {
  const f = await fixture();
  try {
    const empty = 'Bolyra ' + Buffer.from('{}').toString('base64');
    assert.equal(await call(f.host, 'refund', empty), 401);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, false);
    const [receipt] = f.audit.readReceipts();
    assert.equal(receipt.payload.subject.credentialCommitment, '0');
  } finally {
    await f.close();
  }
});

test('redirect is dispatched once and recorded as not_followed (spec test 6)', async () => {
  const f = await fixture('WRITE_DATA', 302);
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, true);
    assert.equal(r.upstreamStatus, 302);
    assert.equal(r.outcome, 'not_followed');
    assert.equal(f.echo.requestCount, 1);
  } finally {
    await f.close();
  }
});

test('allow receipt write failure: 500, not dispatched, receiptError (spec test 10)', async () => {
  const f = await fixture('WRITE_DATA', 200, {
    io: {
      appendFileSync() {
        throw new Error('disk full');
      },
    },
  });
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 500);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'allow');
    assert.equal(r.dispatched, false);
    assert.match(r.receiptError ?? '', /disk full/);
    assert.equal(f.echo.requestCount, 0);
  } finally {
    await f.close();
  }
});

test('permission matrix: granted passes, withheld fails, for every name (spec test 7)', async () => {
  for (const name of PERMISSION_NAMES) {
    const f = await fixture(name);
    try {
      assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200, `${name}: granted`);
      const a = await f.host.nextResult();
      assert.equal(a.decision, 'allow', name);
      assert.equal(await call(f.host, 'refund', buildDevBundle(f.withheld).header), 403, `${name}: withheld`);
      const d = await f.host.nextResult();
      assert.equal(d.stage, 'policy_denied', name);
    } finally {
      await f.close();
    }
  }
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/host'`.

- [ ] **Step 3: Create `src/host.ts`**

```ts
/**
 * The authorization boundary (spec §3.1).
 *
 * A loopback-only server exposing exactly one action. The shipped gateway
 * middleware does bundle verification, nonce replay, dev credential binding,
 * and tool policy, and writes the 401/403 itself; this host duplicates none
 * of those checks. On allow it persists the receipt, then dispatches exactly
 * one HTTP request to the operator's endpoint. Every decision is published
 * to an in-process result channel after its receipt is persisted (or its
 * persistence failure recorded), because a deny's HTTP body carries no
 * receipt id.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  buildDecisionReceiptInput,
  buildDenialReceiptInput,
  createGatewayMiddleware,
} from '@bolyra/gateway';
import type { GatewayConfig, GatewayRequest } from '@bolyra/gateway';
import { verifyReceipt } from '@bolyra/receipts';
import type { Audit } from './audit';
import type { TrialConfig } from './config';

export type Stage =
  | 'missing_auth'
  | 'malformed_bundle'
  | 'verification_failed'
  | 'credential_binding_failed'
  | 'policy_denied';

export type Outcome = 'completed' | 'not_followed' | 'timeout' | 'network_error' | 'not_dispatched';

/** One decision as observed by the host. trial.ts adds `n` and `credential`. */
export interface HostDecision {
  decision: 'allow' | 'deny';
  stage?: Stage;
  /** Middleware reason, or 'allowed'. */
  reason: string;
  /** Status the client saw from the host. */
  httpStatus: number;
  /** The host invoked fetch for this attempt. Not proof of delivery or execution. */
  dispatched: boolean;
  upstreamStatus: number | null;
  outcome: Outcome;
  receiptId: string | null;
  receiptError?: string;
}

export interface HostOptions {
  config: TrialConfig;
  gatewayConfig: GatewayConfig;
  audit: Audit;
  /** Injected for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Upstream timeout in ms (default 15000). */
  timeoutMs?: number;
  log?: (line: string) => void;
}

export interface TrialHost {
  /** Base URL, e.g. http://127.0.0.1:54321 (no trailing slash). */
  url: string;
  /** Total fetch invocations to the operator endpoint. */
  readonly dispatchCount: number;
  /** Every published decision, in order. */
  readonly results: HostDecision[];
  /** Resolves with the next unconsumed decision. */
  nextResult(): Promise<HostDecision>;
  close(): Promise<void>;
}

export async function startHost(opts: HostOptions): Promise<TrialHost> {
  const { config, gatewayConfig, audit } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const log = opts.log ?? (() => {});

  // Created ONCE: createGatewayMiddleware builds its in-memory nonce store
  // when called. Per-request creation would let every replay through.
  const middleware = createGatewayMiddleware({ config: gatewayConfig });

  const descriptor = ` | action=${config.action} ${config.method} ${config.url.host}${config.url.pathname}`;
  const routePath = `/action/${config.action}`;

  const results: HostDecision[] = [];
  const pending: HostDecision[] = [];
  const waiters: Array<(d: HostDecision) => void> = [];
  let dispatchCount = 0;

  function publish(d: HostDecision): void {
    results.push(d);
    const waiter = waiters.shift();
    if (waiter) waiter(d);
    else pending.push(d);
  }

  async function dispatch(): Promise<{ upstreamStatus: number | null; outcome: Outcome }> {
    const init: RequestInit = {
      method: config.method,
      headers: config.headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (config.body) init.body = new Uint8Array(config.body);
    try {
      const res = await fetchImpl(config.url, init);
      await res.arrayBuffer().catch(() => undefined); // drain and discard
      if (res.status >= 300 && res.status < 400) return { upstreamStatus: res.status, outcome: 'not_followed' };
      return { upstreamStatus: res.status, outcome: 'completed' };
    } catch (err) {
      const name = (err as Error).name;
      return { upstreamStatus: null, outcome: name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'network_error' };
    }
  }

  const server = http.createServer(async (incoming, res) => {
    const req = incoming as GatewayRequest;
    try {
      await drain(req);

      if (req.method !== 'POST' || req.url !== routePath) {
        sendJson(res, 404, { error: 'not found' });
        return;
      }

      const ok = await middleware(req, res, config.action);

      if (!ok) {
        const denial = req.bolyraDenial;
        const result: HostDecision = {
          decision: 'deny',
          stage: denial?.stage,
          reason: denial?.reason ?? 'denied: no reason recorded',
          httpStatus: res.statusCode,
          dispatched: false,
          upstreamStatus: null,
          outcome: 'not_dispatched',
          receiptId: null,
        };
        try {
          const input = buildDenialReceiptInput(denial, gatewayConfig, config.action);
          input.reasonCode = (input.reasonCode ?? result.reason) + descriptor;
          result.receiptId = audit.record(input).id;
        } catch (err) {
          result.receiptError = (err as Error).message;
        }
        log(`deny (${result.stage ?? 'unknown'}): ${result.reason}`);
        publish(result);
        return;
      }

      const authCtx = req.bolyra!;
      const bundle = req.bolyraBundle!;
      const input = buildDecisionReceiptInput(bundle, authCtx, gatewayConfig, true, 'allowed' + descriptor);

      let receiptId: string;
      try {
        const receipt = audit.record(input);
        if (!verifyReceipt(receipt, audit.signerInfo.signer)) {
          throw new Error('allow receipt failed re-verification');
        }
        receiptId = receipt.id;
      } catch (err) {
        sendJson(res, 500, { error: 'receipt persistence failed' });
        publish({
          decision: 'allow',
          reason: 'allowed',
          httpStatus: 500,
          dispatched: false,
          upstreamStatus: null,
          outcome: 'not_dispatched',
          receiptId: null,
          receiptError: (err as Error).message,
        });
        return;
      }

      dispatchCount += 1;
      const { upstreamStatus, outcome } = await dispatch();
      log(`allow: dispatched ${config.method} ${config.url.host}${config.url.pathname} -> ${upstreamStatus ?? outcome}`);
      const result: HostDecision = {
        decision: 'allow',
        reason: 'allowed',
        httpStatus: 200,
        dispatched: true,
        upstreamStatus,
        outcome,
        receiptId,
      };
      sendJson(res, 200, { decision: 'allow', dispatched: true, upstreamStatus, outcome, receiptId });
      publish(result);
    } catch (err) {
      log(`host error: ${(err as Error).message}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal trial host error' });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    get dispatchCount() {
      return dispatchCount;
    },
    results,
    nextResult: () =>
      new Promise<HostDecision>((resolve) => {
        const ready = pending.shift();
        if (ready) resolve(ready);
        else waiters.push(resolve);
      }),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function drain(req: http.IncomingMessage): Promise<void> {
  return new Promise((resolve, reject) => {
    req.on('data', () => undefined);
    req.on('end', () => resolve());
    req.on('error', reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}
```

- [ ] **Step 4: Run the tests**

Run: `npm test`
Expected: all pass. The permission-matrix test starts eight hosts; allow up to ~10 s.

If the replay test fails with a 200 on the second call, the middleware was created per request; check that `createGatewayMiddleware` is called exactly once in `startHost`.

- [ ] **Step 5: Commit**

```bash
git add examples/operator-trial/src/host.ts examples/operator-trial/test/host.test.ts
git commit -s -m "operator-trial: authorization host with result channel and single dispatch"
```

### Task 7: runTrial and the CLI

**Files:**
- Create: `examples/operator-trial/src/trial.ts`
- Create: `examples/operator-trial/src/cli.ts`
- Create: `examples/operator-trial/test/trial.test.ts`

- [ ] **Step 1: Write the failing test `test/trial.test.ts`**

```ts
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifyReceipt, verifyReceiptChain } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { runTrial } from '../src/trial';
import { validateTrialConfig } from '../src/config';

const ROOT = path.join(__dirname, '..', '..');

function outDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'trial-run-'));
}

function receiptsIn(runDir: string): SignedReceipt[] {
  return fs.readFileSync(path.join(runDir, 'receipts.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

test('dry run: allow, policy deny, replay deny; 1/0/0; verifiable bundle (spec tests 1-3)', async () => {
  const lines: string[] = [];
  const summary = await runTrial({ outDir: outDir(), dryRun: true, log: (l) => lines.push(l) });
  assert.equal(summary.ok, true, JSON.stringify(summary, null, 2));
  assert.deepEqual(summary.attempts.map((a) => [a.httpStatus, a.decision, a.stage ?? null]), [
    [200, 'allow', null],
    [403, 'deny', 'policy_denied'],
    [401, 'deny', 'verification_failed'],
  ]);
  assert.match(summary.attempts[2].reason, /Nonce already used/);
  assert.deepEqual(summary.dispatchCounts, [1, 0, 0]);
  assert.equal(summary.echoRequestCount, 1);

  const receipts = receiptsIn(summary.runDir);
  const signer = JSON.parse(fs.readFileSync(path.join(summary.runDir, 'signer.json'), 'utf8')).signer;
  assert.equal(receipts.length, 3);
  for (const r of receipts) assert.ok(verifyReceipt(r, signer));
  const chain = verifyReceiptChain(receipts, { expectedSigner: signer, expectedCount: 3 });
  assert.equal(chain.ok, true);
  const verify = fs.readFileSync(path.join(summary.runDir, 'VERIFY.txt'), 'utf8');
  assert.match(verify, /--expect-count 3/);
  assert.match(verify, new RegExp(`--expect-head ${chain.headHash}`));
  assert.equal(summary.verifyCommand?.trim(), verify.trim());

  const text = lines.join('\n');
  assert.match(text, /Attempt 1 .*ALLOW/);
  assert.match(text, /Attempt 3 .*DENY/);
  assert.match(text, /dispatches to your endpoint: 1 \/ 0 \/ 0/);
  assert.match(text, /hello@bolyra\.ai/);
  assert.match(text, /ZK proof verification is disabled/);
  assert.match(text, /does not stop anyone from calling the endpoint directly/);
});

test('dry run with a 302 endpoint records not_followed (spec test 6)', async () => {
  const summary = await runTrial({ outDir: outDir(), dryRun: true, echo: { status: 302 }, log: () => undefined });
  assert.equal(summary.attempts[0].outcome, 'not_followed');
  assert.equal(summary.attempts[0].upstreamStatus, 302);
  assert.deepEqual(summary.dispatchCounts, [1, 0, 0]);
  assert.equal(summary.ok, true);
});

test('secret exclusion: a header value never reaches the bundle or the log (spec test 8)', async () => {
  const dir = outDir();
  const config = validateTrialConfig(
    { action: 'refund', method: 'POST', url: 'http://127.0.0.1:9/replaced-by-echo', headers: { Authorization: 'Bearer ${T}' }, requiredPermission: 'WRITE_DATA' },
    dir,
    { T: 'sekrit-value-77' },
  );
  const lines: string[] = [];
  // dryRun with a config: the echo URL replaces the configured URL, headers are kept.
  const summary = await runTrial({ config, outDir: dir, dryRun: true, log: (l) => lines.push(l) });
  assert.equal(summary.ok, true);
  for (const name of fs.readdirSync(summary.runDir)) {
    const content = fs.readFileSync(path.join(summary.runDir, name), 'utf8');
    assert.equal(content.includes('sekrit-value-77'), false, `${name} leaks the secret`);
  }
  assert.equal(lines.join('\n').includes('sekrit-value-77'), false, 'log leaks the secret');
  assert.match(lines.join('\n'), /headers sent: Authorization/);
});

test('deny-receipt write failure produces a partial but verifiable bundle (spec test 11)', async () => {
  let calls = 0;
  const summary = await runTrial({
    outDir: outDir(),
    dryRun: true,
    log: () => undefined,
    audit: {
      io: {
        appendFileSync(p, data) {
          calls += 1;
          if (calls === 2) {
            fs.appendFileSync(p, data.slice(0, 20));
            throw new Error('disk full');
          }
          fs.appendFileSync(p, data);
        },
      },
    },
  });
  assert.equal(summary.ok, false);
  assert.equal(summary.attempts[0].receiptId !== null, true);
  assert.match(summary.attempts[1].receiptError ?? '', /disk full/);
  assert.match(summary.attempts[2].receiptError ?? '', /chain broken/);
  assert.equal(receiptsIn(summary.runDir).length, 1);
  assert.match(fs.readFileSync(path.join(summary.runDir, 'VERIFY.txt'), 'utf8'), /--expect-count 1/);
});

test('cli: --dry-run exits 0; missing --config exits 2 (spec test 9 at the CLI edge)', () => {
  const cli = path.join(ROOT, 'dist', 'src', 'cli.js');
  const ok = spawnSync(process.execPath, [cli, '--dry-run', '--out-dir', outDir()], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(ok.status, 0, ok.stderr);
  const bad = spawnSync(process.execPath, [cli], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--config/);
  const missingEnv = spawnSync(process.execPath, [cli, '--config', path.join(ROOT, 'trial.example.yaml'), '--out-dir', outDir()], {
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, THEIR_TOKEN: '' } as NodeJS.ProcessEnv,
  });
  // THEIR_TOKEN set but empty is allowed; unset must fail. Unset it explicitly:
  const env = { ...process.env } as Record<string, string | undefined>;
  delete env.THEIR_TOKEN;
  const unset = spawnSync(process.execPath, [cli, '--config', path.join(ROOT, 'trial.example.yaml'), '--out-dir', outDir()], {
    encoding: 'utf8',
    timeout: 60_000,
    env,
  });
  assert.equal(unset.status, 2, unset.stderr);
  assert.match(unset.stderr, /THEIR_TOKEN/);
  void missingEnv;
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test`
Expected: `tsc` fails with `Cannot find module '../src/trial'`.

- [ ] **Step 3: Create `src/trial.ts`**

```ts
/**
 * runTrial (spec §3.2): the operator's three attempts, in-process. The CLI
 * and the tests both call this; nothing here calls process.exit.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildDevBundle,
  createDemoAgent,
  requiredMask,
  withheldLabel,
  withheldMask,
} from './agents';
import { Audit } from './audit';
import type { AuditIo, SummaryAttempt } from './audit';
import { TrialConfigError } from './config';
import type { TrialConfig } from './config';
import { startEcho } from './echo';
import type { EchoServer } from './echo';
import { buildGatewayConfig } from './gateway-config';
import { startHost } from './host';
import type { HostDecision, TrialHost } from './host';
import { CLI_VERSION } from './versions';

export type Credential = 'granted' | 'withheld' | 'replay';

export interface AttemptResult extends HostDecision {
  n: 1 | 2 | 3;
  credential: Credential;
  /** fetch invocations to the operator endpoint during this attempt. */
  dispatches: number;
}

export interface RunTrialOptions {
  /** Required unless dryRun. In dryRun with a config, the URL is replaced by the echo endpoint. */
  config?: TrialConfig;
  /** Parent of the per-run directory. */
  outDir: string;
  dryRun: boolean;
  /** Dry-run only: echo response status (default 200). */
  echo?: { status: number };
  /** Narration sink (default console.log). */
  log?: (line: string) => void;
  /** Test hooks. */
  fetchImpl?: typeof fetch;
  audit?: { io?: Partial<AuditIo> };
}

export interface TrialSummary {
  ok: boolean;
  runDir: string;
  attempts: AttemptResult[];
  dispatchCounts: [number, number, number];
  /** Dry-run only: requests the echo endpoint observed. */
  echoRequestCount: number | null;
  receiptCount: number | null;
  headReceiptHash: string | null;
  verifyCommand: string | null;
  finalizeReason?: string;
}

export async function runTrial(opts: RunTrialOptions): Promise<TrialSummary> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const startedAt = new Date();

  let echo: EchoServer | undefined;
  let config: TrialConfig;
  if (opts.dryRun) {
    echo = await startEcho(opts.echo);
    config = opts.config
      ? { ...opts.config, url: new URL(echo.url) }
      : {
          action: 'echo-action',
          method: 'POST',
          url: new URL(echo.url),
          headers: {},
          requiredPermission: 'WRITE_DATA',
          secrets: [],
        };
  } else {
    if (!opts.config) throw new TrialConfigError('a config is required unless --dry-run is set');
    config = opts.config;
  }

  const runDir = path.join(opts.outDir, startedAt.toISOString().replace(/[:.]/g, '-'));
  if (fs.existsSync(runDir)) {
    if (echo) await echo.close();
    throw new TrialConfigError(`run directory already exists: ${runDir}`);
  }

  const required = requiredMask(config.requiredPermission);
  const granted = createDemoAgent('granted', required);
  const withheld = createDemoAgent('withheld', withheldMask(config.requiredPermission));
  const gatewayConfig = buildGatewayConfig(config.action, required, granted, withheld);
  const audit = new Audit({ runDir, gatewayConfig, io: opts.audit?.io });

  log('Bolyra operator trial');
  log(`  action:   ${config.action}  ${config.method} ${config.url.host}${config.url.pathname}${opts.dryRun ? '  (dry run: built-in echo endpoint)' : ''}`);
  log(`  policy:   ${config.action} requires ${config.requiredPermission}`);
  log(`  headers sent: ${Object.keys(config.headers).join(', ') || '(none)'}`);
  log(`  receipts: ${path.relative(process.cwd(), audit.receiptsPath)}  signer ${audit.signerInfo.signer} (ephemeral, ES256K)`);
  log('');
  log('  Controlled trial: credentials are simulated and registered locally; ZK proof verification is disabled (dev mode).');
  log('  The trial protects traffic routed through this local Bolyra host. It does not stop anyone from calling the endpoint directly.');
  log('');

  const host = await startHost({ config, gatewayConfig, audit, fetchImpl: opts.fetchImpl });
  const attempts: AttemptResult[] = [];
  try {
    const first = buildDevBundle(granted);
    attempts.push(await attempt(host, config, 1, 'granted', first.header));
    attempts.push(await attempt(host, config, 2, 'withheld', buildDevBundle(withheld).header));
    attempts.push(await attempt(host, config, 3, 'replay', first.header));
  } finally {
    await host.close();
    if (echo) await echo.close();
  }

  const dispatchCounts: [number, number, number] = [attempts[0].dispatches, attempts[1].dispatches, attempts[2].dispatches];
  const attemptsOk = expectationsMet(attempts) && dispatchCounts.join() === '1,0,0';

  const finishedAt = new Date();
  const fin = audit.finalize({
    attemptsOk,
    attempts: attempts.map(toSummaryAttempt),
    dispatchCounts,
    dryRun: opts.dryRun,
    action: { name: config.action, method: config.method, host: config.url.host, path: config.url.pathname },
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    secrets: config.secrets,
  });

  const summary: TrialSummary = {
    ok: attemptsOk && fin.ok,
    runDir,
    attempts,
    dispatchCounts,
    echoRequestCount: echo ? echo.requestCount : null,
    receiptCount: fin.receiptCount,
    headReceiptHash: fin.headReceiptHash,
    verifyCommand: fin.verifyCommand,
    finalizeReason: fin.reason,
  };

  narrate(log, config, summary, opts.dryRun);
  return summary;
}

async function attempt(
  host: TrialHost,
  config: TrialConfig,
  n: 1 | 2 | 3,
  credential: Credential,
  authHeader: string,
): Promise<AttemptResult> {
  const before = host.dispatchCount;
  const res = await fetch(`${host.url}/action/${config.action}`, {
    method: 'POST',
    headers: { authorization: authHeader, 'content-type': 'application/json' },
    body: '{}',
  });
  await res.arrayBuffer();
  const decision = await host.nextResult();
  return { n, credential, ...decision, dispatches: host.dispatchCount - before };
}

function expectationsMet(a: AttemptResult[]): boolean {
  const [one, two, three] = a;
  return (
    one.decision === 'allow' && one.dispatched && !one.receiptError &&
    two.decision === 'deny' && two.stage === 'policy_denied' && !two.dispatched && !two.receiptError &&
    three.decision === 'deny' && three.stage === 'verification_failed' && /Nonce already used/.test(three.reason) && !three.dispatched && !three.receiptError
  );
}

function toSummaryAttempt(a: AttemptResult): SummaryAttempt {
  const { dispatches: _dispatches, ...rest } = a;
  return rest;
}

function narrate(log: (l: string) => void, config: TrialConfig, s: TrialSummary, dryRun: boolean): void {
  const labels: Record<Credential, string> = {
    granted: `credential granted ${config.requiredPermission}`,
    withheld: `credential granted ${withheldLabel(config.requiredPermission)}`,
    replay: "replay of attempt 1's bundle",
  };
  for (const a of s.attempts) {
    const verdict = a.decision === 'allow' && a.dispatched ? 'ALLOW' : a.decision === 'allow' ? 'ALLOW (receipt failed)' : 'DENY';
    const upstream = a.dispatched ? `upstream ${a.upstreamStatus ?? a.outcome}` : '';
    const receipt = a.receiptId ? `receipt ${a.receiptId.slice(0, 8)}…` : `receipt error: ${a.receiptError ?? 'unknown'}`;
    log(`Attempt ${a.n}  ${labels[a.credential].padEnd(40)} -> ${verdict.padEnd(6)} dispatched: ${a.dispatched ? 'yes' : 'no '}  ${upstream.padEnd(13)} ${receipt}`);
  }
  log('');
  log(`dispatches to your endpoint: ${s.dispatchCounts.join(' / ')}`);
  if (fs.existsSync(s.runDir)) log(`bundle: ${path.relative(process.cwd(), s.runDir)}/`);
  if (s.verifyCommand) {
    log(`verify independently (needs @bolyra/cli ${CLI_VERSION}; the first npx run downloads it):`);
    log(`  ${s.verifyCommand}`);
  }
  if (!s.ok) log(`RESULT: FAILED${s.finalizeReason ? ` (${s.finalizeReason})` : ''}`);
  log('');
  log('Receipts verify signed claims and chain integrity against the signer in signer.json, which is ephemeral to this run.');
  log('summary.json is unsigned observation; endpoint execution is not proven by the receipts.');
  if (dryRun) {
    log('This was a dry run against the built-in echo endpoint. It does not count toward anything. Point trial.yaml at a staging endpoint or a reversible action you own and run again.');
  } else {
    log('If this ran against an endpoint you own, email the bundle directory to hello@bolyra.ai. Nothing is sent automatically.');
  }
}
```

- [ ] **Step 4: Create `src/cli.ts`**

```ts
#!/usr/bin/env node
/**
 * CLI wrapper: arg parsing and exit codes only.
 *   2  config error (nothing started)
 *   1  the trial ran and did not meet expectations, or an internal error
 *   0  success
 */

import { parseArgs } from 'node:util';
import * as path from 'node:path';
import { loadTrialConfig, TrialConfigError } from './config';
import { runTrial } from './trial';

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      config: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'out-dir': { type: 'string', default: './trial-out' },
    },
    strict: true,
  });
  const dryRun = values['dry-run'] === true;
  if (!dryRun && !values.config) {
    throw new TrialConfigError('--config <trial.yaml> is required unless --dry-run is set');
  }
  const config = values.config ? loadTrialConfig(values.config) : undefined;
  const summary = await runTrial({ config, outDir: path.resolve(values['out-dir'] as string), dryRun });
  process.exitCode = summary.ok ? 0 : 1;
}

main().catch((err: unknown) => {
  if (err instanceof TrialConfigError) {
    console.error(`config error: ${err.message}`);
    process.exitCode = 2;
  } else {
    console.error(`trial error: ${(err as Error).message}`);
    process.exitCode = 1;
  }
});
```

Note: with `--config` and `--dry-run` together the config's headers and permission are used but its URL is replaced by the echo endpoint. That is how test 8 runs without a real endpoint.

- [ ] **Step 5: Run the tests**

Run: `npm test`
Expected: all pass across all test files. Then run the operator path by hand:

Run: `npm run trial -- --dry-run`
Expected: three attempt lines (ALLOW / DENY / DENY), `dispatches to your endpoint: 1 / 0 / 0`, a bundle path under `trial-out/`, a verify command, exit code 0 (`echo $?`).

Run the printed verify command from inside the run directory (it downloads `@bolyra/cli@0.9.0` on first use):
Expected: the CLI reports the chain verified with count 3.

- [ ] **Step 6: Commit**

```bash
git add examples/operator-trial/src/trial.ts examples/operator-trial/src/cli.ts examples/operator-trial/test/trial.test.ts
git commit -s -m "operator-trial: runTrial, narration, and CLI"
```

---

## Chunk 3: README, entry page, CI, lockfile, hand-off

### Task 8: README

**Files:**
- Create: `examples/operator-trial/README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# Bolyra operator trial

Put one HTTP action you own behind a Bolyra authorization rule. Attempt it three ways. See, for each attempt, the decision, whether a request was dispatched to your endpoint, and the signed receipt. About ten minutes once you have endpoint credentials.

**Use a staging endpoint or a reversible action. Attempt 1 really executes.**

## Run it

```bash
git clone https://github.com/bolyra/bolyra
cd bolyra/examples/operator-trial
npm ci
npm run trial -- --dry-run            # built-in echo endpoint, no secrets, see the mechanics
cp trial.example.yaml trial.yaml      # edit: your endpoint, method, header, permission
THEIR_TOKEN=... npm run trial -- --config ./trial.yaml
```

Requires Node 20 or newer on macOS or Linux. Windows is untested.

## What happens

1. The trial mints two simulated credentials and registers them with a local Bolyra host: one granted the permission your action requires, one granted only the tier below it.
2. **Attempt 1** presents the granted credential. The host verifies it, signs an allow receipt, then dispatches your configured request once. You see the upstream status.
3. **Attempt 2** presents the withheld credential. Policy denies it (403). Nothing is dispatched. A deny receipt is signed.
4. **Attempt 3** replays attempt 1's exact proof bundle. Nonce replay protection denies it (401). Nothing is dispatched. A deny receipt is signed.
5. The run ends with `dispatches to your endpoint: 1 / 0 / 0`, a bundle directory, and the command to verify the receipt chain independently.

## The config (`trial.yaml`)

| Key | Required | Rule |
|---|---|---|
| `action` | yes | `^[a-z][a-z0-9_-]{0,63}$`; the name Bolyra gates, recorded in every receipt |
| `method` | yes | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, or `DELETE` |
| `url` | yes | `http` or `https`; no credentials in the URL |
| `headers` | no | map of header name to value; `${NAME}` is replaced from the environment, unset is an error |
| `bodyFile` | no | path relative to the config file, sent byte for byte; not allowed with `GET`, `HEAD`, `DELETE` |
| `requiredPermission` | yes | `READ_DATA`, `WRITE_DATA`, `FINANCIAL_SMALL`, `FINANCIAL_MEDIUM`, `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, `SUB_DELEGATE`, `ACCESS_PII` |

Unknown keys are rejected. Redirects are not followed. There are no retries. The upstream timeout is 15 seconds.

## The bundle

`trial-out/<timestamp>/`:

- `receipts.jsonl`: three ES256K-signed, hash-chained receipts (allow and both denies).
- `signer.json`: the ephemeral signer for this run.
- `summary.json`: unsigned observations: the action (method, host, path), each attempt's decision, dispatch flag, upstream status, and receipt id.
- `VERIFY.txt`: the exact command to verify the chain with `@bolyra/cli`.

Verify independently (the first `npx` run downloads the CLI):

```bash
cd trial-out/<timestamp>
npx @bolyra/cli@0.9.0 receipt verify-chain ./receipts.jsonl --signer <signer> --expect-count 3 --expect-head <hash>
```

Header values, body content, credentials, and upstream response bodies are never written to the bundle or the console. The trial scans the bundle for every value it substituted from the environment and every header value it sent, and deletes the directory on a hit. That scan covers only values the trial itself resolved.

**If this ran against an endpoint you own, email the bundle directory to hello@bolyra.ai.** Nothing is sent automatically.

## What this is, and is not

- A controlled trial. Credentials are simulated and registered locally; ZK proof verification is disabled (dev mode). Production Bolyra uses real proofs and a credential registry.
- It protects traffic routed through the local Bolyra host. It does not stop anyone from calling your endpoint directly.
- Receipts verify signed claims and chain integrity against the signer in `signer.json`, which is ephemeral to this run. Endpoint execution is an unsigned observation in `summary.json`.
- Not a hosted service, not a certification, not a production deployment.

## Under the hood

The host embeds `createGatewayMiddleware` from the published `@bolyra/gateway` (bundle verification, nonce replay, dev credential binding, tool policy) and signs receipts with `@bolyra/receipts`. See `src/host.ts`. Spec: `docs/superpowers/specs/2026-09-13-operator-trial-design.md`.
```

- [ ] **Step 2: Check every command in the README against what Task 7 produced**

Run: `npm run trial -- --dry-run` again and compare the narration with the README's "What happens" list. Fix the README, not the code, if wording differs.

- [ ] **Step 3: Commit**

```bash
git add examples/operator-trial/README.md
git commit -s -m "operator-trial: README with the operator path and honesty labels"
```

### Task 9: Entry page

**Files:**
- Create: `landing/operator-trial.html`
- Modify: `landing/deploy.sh` (add the page to the upload list, next to `CONFORMANCE`)

- [ ] **Step 1: Read `landing/deploy.sh`** around the `CONFORMANCE=` variable (line ~36) and the `aws s3 cp "$CONFORMANCE"` block (line ~158) to see how one extra page is uploaded.

- [ ] **Step 2: Create `landing/operator-trial.html`**

Reuse the head, `:root` tokens, `body`, `main`, `a`, `h1`, `.lede`, `.notice`, `code`, and `footer` rules from `landing/conformance.html` verbatim (copy lines 1 through the end of `<style>`). Then the body:

```html
<body>
<main>
  <p><a href="/">&larr; bolyra.ai</a></p>
  <h1>Operator trial</h1>
  <p class="lede">Put one HTTP action you own behind a Bolyra authorization rule. Attempt it three ways. See the decision, whether a request reached your endpoint, and the signed receipt, for each.</p>
  <p class="notice">Use a staging endpoint or a reversible action. Attempt 1 really executes.</p>

  <h2>Run it</h2>
  <pre><code>git clone https://github.com/bolyra/bolyra
cd bolyra/examples/operator-trial
npm ci
npm run trial -- --dry-run
cp trial.example.yaml trial.yaml   # your endpoint, method, header, permission
THEIR_TOKEN=... npm run trial -- --config ./trial.yaml</code></pre>
  <p>Node 20 or newer, macOS or Linux. About ten minutes once you have endpoint credentials.</p>

  <h2>What you see</h2>
  <pre><code>Attempt 1  credential granted WRITE_DATA        -> ALLOW   dispatched: yes  upstream 201  receipt a1b2…
Attempt 2  credential granted READ_DATA only    -> DENY    dispatched: no                 receipt c3d4…
Attempt 3  replay of attempt 1's bundle         -> DENY    dispatched: no                 receipt e5f6…

dispatches to your endpoint: 1 / 0 / 0
bundle: trial-out/2026-09-13T15-40-12Z/
verify independently:
  npx @bolyra/cli@0.9.0 receipt verify-chain ./receipts.jsonl --signer 0x… --expect-count 3 --expect-head 0x…</code></pre>

  <h2>What it is, and is not</h2>
  <ul>
    <li>A controlled trial: credentials are simulated and registered locally; ZK proof verification is disabled. Production Bolyra uses real proofs and a credential registry.</li>
    <li>It protects traffic routed through the local Bolyra host. It does not stop anyone from calling your endpoint directly.</li>
    <li>Receipts verify signed claims and chain integrity against an ephemeral signer. Endpoint execution is an unsigned observation.</li>
    <li>Header values, bodies, and credentials never leave your machine and never enter the bundle. Nothing is sent automatically.</li>
  </ul>

  <p>If it ran against an endpoint you own, email the bundle directory to <a href="mailto:hello@bolyra.ai">hello@bolyra.ai</a>. Full details: <a href="https://github.com/bolyra/bolyra/tree/main/examples/operator-trial">examples/operator-trial</a>.</p>

  <footer>Bolyra (ZKProva Inc.) — Apache-2.0.</footer>
</main>
</body>
</html>
```

Add `h2 { font-size: 1.25rem; margin: 32px 0 12px; } pre { background: var(--bg-code); border: 1px solid var(--border); border-radius: 12px; padding: 16px; overflow-x: auto; } ul { padding-left: 20px; } li { margin-bottom: 8px; }` to the copied `<style>`.

- [ ] **Step 3: Add the page to `landing/deploy.sh`**

Next to `CONFORMANCE="$SCRIPT_DIR/conformance.html"` add `OPERATOR_TRIAL="$SCRIPT_DIR/operator-trial.html"`, and next to the `aws s3 cp "$CONFORMANCE" "s3://$BUCKET/conformance.html"` block add an identical block for `"$OPERATOR_TRIAL"` to `operator-trial.html` with the same flags. Do not change anything else in the script and do not run it; deploying is the founder's action.

- [ ] **Step 4: Open the page locally and check both themes render** (`open landing/operator-trial.html`). The page must not scroll horizontally on a 390px-wide window; the `<pre>` blocks scroll inside themselves.

- [ ] **Step 5: Commit**

```bash
git add landing/operator-trial.html landing/deploy.sh
git commit -s -m "landing: operator trial entry page"
```

### Task 10: CI job and a Linux-clean lockfile

**Files:**
- Modify: `.github/workflows/ci.yml` (add a job after `verified-actions-demo`, around line 506)
- Modify: `examples/operator-trial/package-lock.json` (regenerate on Linux)

- [ ] **Step 1: Add the CI job** immediately after the `verified-actions-demo` job:

```yaml
  operator-trial:
    name: Operator trial — dry run and tests from a clean checkout
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1

      - uses: actions/setup-node@v7
        with:
          node-version: 20

      # The trial is what the operator entry page promises. It depends on the
      # PUBLISHED @bolyra packages, so this proves the README path works with
      # nothing else in the repo built. The dry run exits non-zero if any
      # attempt verdict, dispatch count, or chain check comes out wrong.
      - name: Install, dry-run the trial, run its tests
        working-directory: examples/operator-trial
        run: |
          npm ci --no-audit --no-fund
          npm run trial -- --dry-run
          npm test
```

- [ ] **Step 2: Regenerate the lockfile on Linux** so `scripts/verify-lockfiles.sh` (the `lockfiles` CI job) passes. From the repo root:

```bash
docker run --rm -v "$PWD/examples/operator-trial":/w -w /w node:20 sh -c 'rm -rf node_modules package-lock.json && npm install --no-audit --no-fund --package-lock-only && npm ci --no-audit --no-fund'
```

Expected: exits 0 and leaves a `package-lock.json` that `npm ci` accepts on Linux. Then, still from the repo root:

Run: `bash scripts/verify-lockfiles.sh`
Expected: `examples/operator-trial` listed as passing; exit 0.

- [ ] **Step 3: Re-run the package tests locally with the regenerated lockfile**

Run: `cd examples/operator-trial && rm -rf node_modules && npm ci && npm test`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml examples/operator-trial/package-lock.json
git commit -s -m "ci: operator-trial job; Linux-clean lockfile"
```

### Task 11: Hand-off

**Files:**
- Modify: `tasks/todo.md` (append the checklist and a review section)
- Modify: `CLAUDE.md` (one line under "Verified Agent Actions": the trial exists and where)

- [ ] **Step 1: Append to `tasks/todo.md`**

```markdown
## Operator authorization trial (2026-09-13, Codex-ruled build, spec docs/superpowers/specs/2026-09-13-operator-trial-design.md)
- [x] Scaffold, versions, agents, config, echo (Chunk 1)
- [x] Audit with rollback, host with result channel, runTrial + CLI (Chunk 2)
- [x] README, landing/operator-trial.html, CI job, Linux lockfile (Chunk 3)
- [ ] Founder: deploy landing (`landing/deploy.sh`), add one link to the trial in the next outreach
- [ ] 30-day metric (from ship date): ≥1 external workflow owner emails a bundle from their own endpoint. Dry-runs and vendor runs do not count.

## Review (operator trial)
Hours spent: ___ of the 20h cap. Deviations from spec: ___. Anything cut to stay under the cap: ___.
```

- [ ] **Step 2: Add to `CLAUDE.md`** under the "Verified Agent Actions (EVC + MPP)" bullets:

```markdown
- **operator-trial** (`examples/operator-trial/`) — clone-and-run: one HTTP action an operator owns behind `createGatewayMiddleware`, three attempts (allow / policy deny / replay deny), signed receipt chain, exportable bundle. Entry page `landing/operator-trial.html`. Metric: one external operator completes it on their own endpoint (bundle emailed to hello@bolyra.ai).
```

- [ ] **Step 3: Full verification from a clean state**

From the repo root:

```bash
cd examples/operator-trial && rm -rf node_modules dist trial-out && npm ci --no-audit --no-fund && npm run trial -- --dry-run && npm test; echo "exit $?"
```

Expected: dry run narrates three attempts and `1 / 0 / 0`; tests all pass; final `exit 0`.

- [ ] **Step 4: Commit and push the branch, open a draft PR**

```bash
git add tasks/todo.md CLAUDE.md
git commit -s -m "docs: operator trial in todo and CLAUDE.md"
git push -u origin worktree-operator-trial
gh pr create --draft --title "examples: operator authorization trial" --body "$(cat <<'EOF'
Codex-ruled next build (2026-09-13): a clone-and-run trial that puts one HTTP action an operator owns behind Bolyra authorization, runs allow / policy-deny / replay attempts, signs a receipt chain, and exports a verifiable bundle.

Spec: docs/superpowers/specs/2026-09-13-operator-trial-design.md
Plan: docs/superpowers/plans/2026-09-13-operator-trial.md

- examples/operator-trial (private example, published deps pinned, node:test, 13 spec tests)
- landing/operator-trial.html (entry page; deploy is a separate founder action)
- CI: operator-trial job (clean checkout, dry run, tests)

Metric: one external workflow owner completes it on their own endpoint within 30 days.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01QyczbUJCLe521EC3kv1dvS
EOF
)"
```

Expected: PR URL printed. CI jobs `operator-trial`, `lockfiles`, `dco`, `typecheck-all` must go green before the PR leaves draft.
