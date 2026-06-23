/**
 * bolyra doctor — health check for the Bolyra setup.
 *
 * Checks Node version, packages, receipt store, policy files,
 * GitHub Action config, and environment.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

interface Check {
  status: 'ok' | 'warn' | 'fail';
  label: string;
  detail: string;
}

export async function run(_argv: string[]): Promise<void> {
  const checks: Check[] = [];

  // 1. Node version
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1), 10);
  if (major >= 18) {
    checks.push({ status: 'ok', label: 'Node.js', detail: `${nodeVersion} (>= 18 required)` });
  } else {
    checks.push({ status: 'fail', label: 'Node.js', detail: `${nodeVersion} — need >= 18` });
  }

  // 2. CLI version
  try {
    const pkg = require('../../package.json');
    checks.push({ status: 'ok', label: 'CLI installed', detail: `@bolyra/cli ${pkg.version}` });
  } catch {
    checks.push({ status: 'fail', label: 'CLI installed', detail: 'cannot read package.json' });
  }

  // 3. @bolyra/shield availability
  try {
    const shieldPkg = require('@bolyra/shield/package.json');
    checks.push({ status: 'ok', label: 'Shield package', detail: `@bolyra/shield ${shieldPkg.version}` });
  } catch {
    try {
      execSync('npx @bolyra/shield --version', { timeout: 5000, stdio: 'pipe' });
      checks.push({ status: 'ok', label: 'Shield package', detail: 'available via npx' });
    } catch {
      checks.push({ status: 'warn', label: 'Shield package', detail: 'not installed (install: npm i @bolyra/shield)' });
    }
  }

  // 4. @bolyra/mcp availability
  try {
    const mcpPkg = require('@bolyra/mcp/package.json');
    checks.push({ status: 'ok', label: 'MCP package', detail: `@bolyra/mcp ${mcpPkg.version}` });
  } catch {
    checks.push({ status: 'warn', label: 'MCP package', detail: 'not installed (install: npm i @bolyra/mcp)' });
  }

  // 5. @bolyra/gateway availability
  try {
    const gwPkg = require('@bolyra/gateway/package.json');
    checks.push({ status: 'ok', label: 'Gateway package', detail: `@bolyra/gateway ${gwPkg.version}` });
  } catch {
    checks.push({ status: 'warn', label: 'Gateway package', detail: 'not installed (install: npm i @bolyra/gateway)' });
  }

  // 6. Receipt store
  const receiptDir = path.join(os.homedir(), '.bolyra', 'receipts');
  if (fs.existsSync(receiptDir)) {
    try {
      const testFile = path.join(receiptDir, '.doctor-test');
      fs.writeFileSync(testFile, '');
      fs.unlinkSync(testFile);

      // Count receipts
      const files = fs.readdirSync(receiptDir).filter(f => f.endsWith('.ndjson') || f.endsWith('.jsonl'));
      const indexFile = path.join(receiptDir, 'index.json');
      let sessions = 0;
      if (fs.existsSync(indexFile)) {
        try { sessions = JSON.parse(fs.readFileSync(indexFile, 'utf-8')).length; } catch { /* skip */ }
      }
      checks.push({ status: 'ok', label: 'Receipt store', detail: `${receiptDir} (${files.length} files, ${sessions} sessions)` });

      // Latest receipt
      if (files.length > 0) {
        const latest = files.sort().pop()!;
        const content = fs.readFileSync(path.join(receiptDir, latest), 'utf-8');
        const lines = content.split('\n').filter(l => l.trim());
        const lastLine = lines[lines.length - 1];
        try {
          const receipt = JSON.parse(lastLine);
          checks.push({ status: 'ok', label: 'Latest receipt', detail: `${latest} (${receipt.decision} ${receipt.toolName ?? ''})` });
        } catch {
          checks.push({ status: 'warn', label: 'Latest receipt', detail: `${latest} (could not parse last line)` });
        }
      }
    } catch {
      checks.push({ status: 'fail', label: 'Receipt store', detail: `${receiptDir} (not writable)` });
    }
  } else {
    checks.push({ status: 'warn', label: 'Receipt store', detail: `${receiptDir} (not created yet — will be created on first bolyra run)` });
  }

  // 7. Policy file
  const policyPaths = ['shield.yaml', 'bolyra.policy.json', 'bolyra.policy.yaml'];
  let foundPolicy = false;
  for (const p of policyPaths) {
    if (fs.existsSync(path.resolve(p))) {
      checks.push({ status: 'ok', label: 'Policy file', detail: p });
      foundPolicy = true;
      break;
    }
  }
  if (!foundPolicy) {
    checks.push({ status: 'warn', label: 'Policy file', detail: 'none found (run: bolyra observe --output shield.yaml)' });
  }

  // 8. GitHub Action
  const actionPaths = [
    '.github/workflows/bolyra-replay.yml',
    '.github/workflows/bolyra-replay.yaml',
    '.github/workflows/bolyra.yml',
    '.github/workflows/bolyra.yaml',
  ];
  let foundAction = false;
  for (const p of actionPaths) {
    if (fs.existsSync(path.resolve(p))) {
      checks.push({ status: 'ok', label: 'GitHub Action', detail: p });
      foundAction = true;
      break;
    }
  }
  // Also check if any workflow references bolyra
  if (!foundAction) {
    const workflowDir = path.resolve('.github/workflows');
    if (fs.existsSync(workflowDir)) {
      try {
        const files = fs.readdirSync(workflowDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
        for (const f of files) {
          const content = fs.readFileSync(path.join(workflowDir, f), 'utf-8');
          if (content.includes('bolyra') || content.includes('replay-check')) {
            checks.push({ status: 'ok', label: 'GitHub Action', detail: `.github/workflows/${f}` });
            foundAction = true;
            break;
          }
        }
      } catch { /* skip */ }
    }
  }
  if (!foundAction) {
    checks.push({ status: 'warn', label: 'GitHub Action', detail: 'not configured (see: bolyra/bolyra/actions/replay-check)' });
  }

  // 9. Credential store
  const credDir = path.join(os.homedir(), '.bolyra', 'credentials');
  if (fs.existsSync(credDir)) {
    const creds = fs.readdirSync(credDir).filter(f => f.endsWith('.json'));
    checks.push({ status: 'ok', label: 'Credential store', detail: `${creds.length} credential(s)` });
  } else {
    checks.push({ status: 'warn', label: 'Credential store', detail: 'empty (run: bolyra cred create)' });
  }

  // Print results
  console.log('Bolyra Doctor\n');

  let hasFailure = false;
  for (const check of checks) {
    let icon: string;
    switch (check.status) {
      case 'ok':   icon = `${GREEN}OK  ${RESET}`; break;
      case 'warn': icon = `${YELLOW}WARN${RESET}`; break;
      case 'fail': icon = `${RED}FAIL${RESET}`; hasFailure = true; break;
    }
    console.log(`${icon}  ${check.label}: ${check.detail}`);
  }

  const okCount = checks.filter(c => c.status === 'ok').length;
  const warnCount = checks.filter(c => c.status === 'warn').length;
  const failCount = checks.filter(c => c.status === 'fail').length;

  console.log(`\nResult: ${okCount} ok, ${warnCount} warnings, ${failCount} failures`);

  if (hasFailure) {
    console.log(`\n${RED}Fix the failures above before using Bolyra.${RESET}`);
    process.exitCode = 1;
  } else if (warnCount > 0) {
    console.log(`\n${YELLOW}Bolyra is ready. Warnings are optional improvements.${RESET}`);
  } else {
    console.log(`\n${GREEN}Bolyra is fully configured.${RESET}`);
  }
}
